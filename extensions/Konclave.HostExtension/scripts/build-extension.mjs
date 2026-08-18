import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { build } from 'esbuild';
import { extensionEntryPath } from './package-contract.mjs';

mkdirSync(dirname(extensionEntryPath), { recursive: true });

await build({
  entryPoints: ['src/extension.ts'],
  outfile: extensionEntryPath,
  bundle: true,
  external: ['@github/copilot-sdk', '@github/copilot-sdk/*'],
  format: 'esm',
  logLevel: 'info',
  platform: 'node',
  sourcemap: false,
  target: 'node24',
  treeShaking: true,
});
