import { spawn } from 'node:child_process';
import { access } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const expected = '{"source":"extension-owned-handler","value":"transport-proof"}';
const spikeDirectory = dirname(fileURLToPath(import.meta.url));
const pluginDirectory = join(spikeDirectory, 'sdk-proxy-plugin');

async function resolveCopilotCommand() {
  const configured = process.env.COPILOT_CLI_PATH;
  if (configured) {
    return { command: configured, prefixArguments: [] };
  }
  if (process.platform !== 'win32') {
    return { command: 'copilot', prefixArguments: [] };
  }

  const loader = join(
    process.env.APPDATA ?? '',
    'npm',
    'node_modules',
    '@github',
    'copilot',
    'npm-loader.js',
  );
  await access(loader);
  return { command: process.execPath, prefixArguments: [loader] };
}

async function main() {
  const { command, prefixArguments } = await resolveCopilotCommand();
  const child = spawn(
    command,
    [
      ...prefixArguments,
      '-p',
      'Call the konclave_sdk_proxy_probe tool exactly once with value transport-proof. Return only the tool JSON result.',
      '--experimental',
      '--plugin-dir',
      pluginDirectory,
      '--allow-all-tools',
    ],
    {
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    },
  );
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    stdout = `${stdout}${chunk}`.slice(-64 * 1024);
  });
  child.stderr.on('data', (chunk) => {
    stderr = `${stderr}${chunk}`.slice(-4 * 1024);
  });

  const timeout = setTimeout(() => child.kill(), 180_000);
  try {
    const code = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', resolve);
    });
    if (code !== 0 || !stdout.includes(expected)) {
      throw new Error(
        `Copilot proxy probe failed with exit ${String(code)}: ${stderr.trim().slice(0, 512)}`,
      );
    }
    console.log('sdk-tool-proxy-probe: Copilot invoked an extension-owned dynamic tool handler.');
  } finally {
    clearTimeout(timeout);
  }
}

await main().catch((error) => {
  const message = error instanceof Error ? error.message : 'unknown failure';
  console.error(`sdk-tool-proxy-probe: ${message.slice(0, 512)}`);
  process.exitCode = 1;
});
