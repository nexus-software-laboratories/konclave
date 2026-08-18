/**
 * Keeps plugin.json in sync after npm changes package.json.
 */
import { readFileSync, writeFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync('package.json', 'utf-8'));
const plugin = JSON.parse(readFileSync('plugin.json', 'utf-8'));

plugin.version = pkg.version;

writeFileSync('plugin.json', JSON.stringify(plugin, null, 2) + '\n');

console.log(`Synced version ${pkg.version} to plugin.json.`);
