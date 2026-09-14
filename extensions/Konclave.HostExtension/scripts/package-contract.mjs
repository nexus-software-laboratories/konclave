export const buildExtensionPath = 'extensions/Konclave.Extension/';
export const extensionEntryPath = `${buildExtensionPath}extension.mjs`;
export const clientEntryPath = `${buildExtensionPath}client.mjs`;
export const genericEntryPath = `${buildExtensionPath}generic.mjs`;
export const genericSkillPath = 'skills/konclave-generic/SKILL.md';
export const maintainerSkillPath = 'skills/copilot-cli-extension-maintainer/SKILL.md';

export const agentPluginExtensionPath = 'com.github.copilot/extensions/konclave/';
export const agentPluginExtensionEntryPath = `${agentPluginExtensionPath}extension.mjs`;
export const agentPluginExtensionPackagePath = `${agentPluginExtensionPath}package.json`;
export const agentPluginArchivePaths = [
  'plugin.json',
  agentPluginExtensionEntryPath,
  agentPluginExtensionPackagePath,
];
export const fixedMtime = new Date('2000-01-01T00:00:00Z');

export function createAgentExtensionPackage(pluginManifest, packageManifest) {
  return {
    name: pluginManifest.name,
    version: pluginManifest.version,
    description: pluginManifest.description,
    type: 'module',
    main: 'extension.mjs',
    license: pluginManifest.license,
    dependencies: {
      '@github/copilot-sdk': packageManifest.dependencies?.['@github/copilot-sdk'],
    },
  };
}

export function getArchivePath(pluginManifest) {
  return `build/outputs/${pluginManifest.name}-${pluginManifest.version}.zip`;
}
