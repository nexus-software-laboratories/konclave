export const manifestExtensionPath = 'extensions/Konclave.Extension/';
export const extensionEntryPath = `${manifestExtensionPath}extension.mjs`;
export const clientEntryPath = `${manifestExtensionPath}client.mjs`;
export const genericEntryPath = `${manifestExtensionPath}generic.mjs`;
export const maintainerSkillPath = 'skills/copilot-cli-extension-maintainer/SKILL.md';
export const genericSkillPath = 'skills/konclave-generic/SKILL.md';
export const packageFiles = [
  'plugin.json',
  clientEntryPath,
  extensionEntryPath,
  genericEntryPath,
  genericSkillPath,
  maintainerSkillPath,
];
export const fixedMtime = new Date('2000-01-01T00:00:00Z');

export function getArchivePath(pluginManifest) {
  return `build/outputs/${pluginManifest.name}-${pluginManifest.version}.zip`;
}
