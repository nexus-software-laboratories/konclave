import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { zipSync } from 'fflate';
import { fixedMtime, getArchivePath, packageFiles } from './package-contract.mjs';

const pluginManifest = JSON.parse(readFileSync('plugin.json', 'utf8'));
const archivePath = getArchivePath(pluginManifest);

mkdirSync(dirname(archivePath), { recursive: true });

const zipInput = {};
for (const filePath of [...packageFiles].sort()) {
  zipInput[filePath] = [readFileSync(filePath), { mtime: fixedMtime }];
}

writeFileSync(archivePath, zipSync(zipInput, { level: 9 }));

console.log(`Packaged ${archivePath}`);
