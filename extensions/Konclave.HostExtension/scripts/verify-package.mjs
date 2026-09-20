import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { unzipSync } from 'fflate';
import {
  agentPluginArchivePaths,
  agentPluginExtensionEntryPath,
  agentPluginExtensionPackagePath,
  clientEntryPath,
  createAgentExtensionPackage,
  extensionEntryPath,
  genericEntryPath,
  genericSkillPath,
  getArchivePath,
  maintainerSkillPath,
} from './package-contract.mjs';

const errors = [];
const semverPattern = /^\d+\.\d+\.\d+$/;
const agentPluginSchema = 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json';
const pluginNamePattern = /^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/;

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
const agentExtensionPackage = createAgentExtensionPackage(pluginManifest, packageManifest);
const allowedManifestFields = new Set([
  '$schema',
  'name',
  'version',
  'description',
  'author',
  'homepage',
  'repository',
  'license',
  'keywords',
  'extensions',
]);

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
  pluginManifest.$schema === agentPluginSchema,
  `plugin.json must target Agent Plugins 1.0: "${agentPluginSchema}".`,
);
check(
  Object.keys(pluginManifest).every((field) => allowedManifestFields.has(field)),
  'plugin.json contains a non-Agent-Plugins field.',
);
check(
  pluginManifest.extensions &&
    typeof pluginManifest.extensions === 'object' &&
    !Array.isArray(pluginManifest.extensions) &&
    Object.keys(pluginManifest.extensions).length === 1 &&
    pluginManifest.extensions['com.github.copilot'] &&
    typeof pluginManifest.extensions['com.github.copilot'] === 'object' &&
    Object.keys(pluginManifest.extensions['com.github.copilot']).length === 0,
  'plugin.json must declare only the empty com.github.copilot namespace.',
);
check(pluginManifest.license === 'Apache-2.0', 'plugin.json must declare the Apache-2.0 license.');
check(
  typeof agentExtensionPackage.dependencies['@github/copilot-sdk'] === 'string' &&
    agentExtensionPackage.dependencies['@github/copilot-sdk'].length > 0,
  'The Copilot extension package must declare its SDK dependency.',
);

for (const filePath of [
  extensionEntryPath,
  clientEntryPath,
  genericEntryPath,
  genericSkillPath,
  maintainerSkillPath,
]) {
  check(existsSync(filePath), `Missing compiled or source support asset: ${filePath}`);
}

const compiledExtension = existsSync(extensionEntryPath)
  ? readFileSync(extensionEntryPath, 'utf8')
  : '';
const compiledClient = existsSync(clientEntryPath) ? readFileSync(clientEntryPath, 'utf8') : '';
const compiledGeneric = existsSync(genericEntryPath) ? readFileSync(genericEntryPath, 'utf8') : '';
const clientApi = existsSync(clientEntryPath)
  ? await import(pathToFileURL(resolve(clientEntryPath)).href)
  : {};

check(
  compiledExtension.includes('joinSession'),
  'Compiled extension is missing the joinSession lifecycle.',
);
check(
  typeof clientApi.connectInstalledService === 'function' &&
    typeof clientApi.connectInstalledGenericService === 'function' &&
    typeof clientApi.validateGenericClientIdentity === 'function' &&
    typeof clientApi.GenericClientIdentityError === 'function' &&
    compiledClient.includes('request.cancel') &&
    typeof clientApi.createKonclaveTools === 'function' &&
    typeof clientApi.createCopilotPolicyGate === 'function' &&
    typeof clientApi.createLocalServiceDeliveryChannel === 'function' &&
    typeof clientApi.frameDelivery === 'function',
  'Compiled client bundle is missing a connector, cancellation, tools, or policy-aware delivery.',
);
check(
  !compiledClient.includes('KonclaveLocalDaemon') && !compiledClient.includes('type: "stdio"'),
  'Compiled client bundle must not contain a per-session daemon path.',
);
check(
  !compiledClient.includes('console.log(') && !compiledClient.includes('process.stdout'),
  'Compiled client bundle must not write to stdout.',
);
const recipeExports = [
  'createRecipeDefinition',
  'decodeRecipeDefinition',
  'createRecipeRun',
  'decodeRecipeRun',
  'recipeMessageId',
  'createRecipeMessaging',
  'RecipeDefinitionError',
  'RecipeRunError',
];
const hasRecipeExports = recipeExports.every((name) => typeof clientApi[name] === 'function');
check(hasRecipeExports, 'Compiled client bundle is missing an external recipe contract.');
if (hasRecipeExports) {
  const definition = clientApi.createRecipeDefinition({
    name: 'package-fixture',
    provider: 'example.fan-out',
    configuration: '',
  });
  const decoded = clientApi.decodeRecipeDefinition(
    Buffer.from(definition.canonicalJson),
    definition.digest,
  );
  const run = clientApi.createRecipeRun(Buffer.from(decoded.canonicalJson), decoded.digest, {
    profile: 'package-fixture',
    nonce: '01'.repeat(16),
    bindings: [
      { name: 'peer', conversationId: '02'.repeat(32), targetDeviceId: '03'.repeat(32) },
    ],
    input: 'Public package fixture.',
  });
  const restored = clientApi.decodeRecipeRun(Buffer.from(run.canonicalJson), run.runId);
  const adapter = clientApi.createRecipeMessaging(
    {
      profile: run.profile,
      connected: true,
      async request() {
        throw new Error('Package verification must not invoke a service operation.');
      },
      retire: async () => undefined,
      close: () => undefined,
    },
    Buffer.from(restored.canonicalJson),
    restored.runId,
  );
  check(
    adapter.run.runId === run.runId &&
      clientApi.recipeMessageId(restored, 'peer') === clientApi.recipeMessageId(run, 'peer'),
    'Compiled recipe definitions and selections must round-trip without service access.',
  );
}
check(
  compiledGeneric.includes('connectInstalledGenericService') &&
    compiledGeneric.includes('request.cancel') &&
    compiledGeneric.includes('account_trusted') &&
    compiledGeneric.includes('integration-label') &&
    compiledGeneric.includes('profile-mode') &&
    compiledGeneric.includes('ephemeral_profile_invalid'),
  'Compiled generic client is missing the identity, grant, or cancellation contract.',
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
  const expectedEntries = [...agentPluginArchivePaths].sort();

  check(
    JSON.stringify(entryNames) === JSON.stringify(expectedEntries),
    `Packaged archive must contain exactly: ${expectedEntries.join(', ')}`,
  );

  const expectedBytes = new Map([
    ['plugin.json', readFileSync('plugin.json')],
    [agentPluginExtensionEntryPath, readFileSync(extensionEntryPath)],
    [
      agentPluginExtensionPackagePath,
      Buffer.from(`${JSON.stringify(agentExtensionPackage, null, 2)}\n`),
    ],
  ]);
  for (const filePath of expectedEntries) {
    const archivedFile = archiveEntries[filePath];
    if (!archivedFile) {
      continue;
    }

    check(
      Buffer.from(archivedFile).equals(expectedBytes.get(filePath)),
      `Packaged archive entry does not match its deterministic source: ${filePath}`,
    );
  }
  check(
    entryNames.every(
      (entry) =>
        !/(^|\/)(?:node_modules|src|tests?|skills|build|coverage)(?:\/|$)/.test(entry) &&
        !/(?:KonclaveLocalDaemon|KonclaveLocalService|konclave\.service\.json)/.test(entry),
    ),
    'Packaged Agent Plugin contains development, native, or mutable authority state.',
  );

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
