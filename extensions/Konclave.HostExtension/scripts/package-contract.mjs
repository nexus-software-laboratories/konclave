export const manifestExtensionPath = 'extensions/Konclave.Extension/';
export const extensionEntryPath = `${manifestExtensionPath}extension.mjs`;
export const manifestSkillsPath = 'skills/';
export const maintainerSkillPath = 'skills/copilot-cli-extension-maintainer/SKILL.md';
export const packageFiles = ['plugin.json', extensionEntryPath, maintainerSkillPath];
export const fixedMtime = new Date('2000-01-01T00:00:00Z');

export function getArchivePath(pluginManifest) {
  return `build/outputs/${pluginManifest.name}-${pluginManifest.version}.zip`;
}
