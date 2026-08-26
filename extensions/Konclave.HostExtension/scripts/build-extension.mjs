import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { build } from 'esbuild';
import { extensionEntryPath } from './package-contract.mjs';

mkdirSync(dirname(extensionEntryPath), { recursive: true });

await build({
  entryPoints: {
    client: 'src/client-api.ts',
    extension: 'src/extension.ts',
  },
  outdir: dirname(extensionEntryPath),
  outExtension: { '.js': '.mjs' },
  bundle: true,
  external: ['@github/copilot-sdk', '@github/copilot-sdk/*'],
  format: 'esm',
  logLevel: 'info',
  platform: 'node',
  sourcemap: false,
  target: 'node24',
  treeShaking: true,
});
