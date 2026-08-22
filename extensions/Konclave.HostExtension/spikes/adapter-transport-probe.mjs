import { spawn } from 'node:child_process';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { chmod, mkdtemp, rm, stat } from 'node:fs/promises';
import { createConnection, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const maximumFrameBytes = 4 * 1024;
const processTimeoutMilliseconds = 30_000;
const profileId = 'probe-profile';
const spikeDirectory = dirname(fileURLToPath(import.meta.url));
const rustSource = join(spikeDirectory, 'adapter_transport_probe.rs');

function capability() {
  return randomBytes(32).toString('base64url');
}

function digest(value) {
  return createHash('sha256').update(value, 'utf8').digest();
}

function fixedTimeEqual(left, right) {
  return timingSafeEqual(digest(left), digest(right));
}

function endpointFor(root) {
  if (process.platform === 'win32') {
    return `\\\\.\\pipe\\konclave-adapter-probe-${randomUUID()}`;
  }
  return join(root, 'adapter.sock');
}

async function runProcess(command, arguments_, options = {}) {
  const child = spawn(command, arguments_, {
    ...options,
    shell: false,
    windowsHide: true,
  });
  let stdout = '';
  let stderr = '';
  child.stdout?.setEncoding('utf8');
  child.stderr?.setEncoding('utf8');
  child.stdout?.on('data', (chunk) => {
    stdout = `${stdout}${chunk}`.slice(-maximumFrameBytes);
  });
  child.stderr?.on('data', (chunk) => {
    stderr = `${stderr}${chunk}`.slice(-maximumFrameBytes);
  });

  const timeout = setTimeout(() => child.kill(), processTimeoutMilliseconds);
  try {
    const code = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', resolve);
    });
    return { code, stdout, stderr };
  } finally {
    clearTimeout(timeout);
  }
}

async function compileProbe(binaryPath) {
  const result = await runProcess(
    process.env.RUSTC ?? 'rustc',
    ['--edition=2024', rustSource, '-o', binaryPath],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  if (result.code !== 0) {
    throw new Error(`Rust probe compilation failed: ${result.stderr.trim().slice(0, 512)}`);
  }
}

async function startAdapterServer(root, expectedToken, expectedProfile) {
  const endpoint = endpointFor(root);
  let accepted = 0;
  let denied = 0;
  const server = createServer((socket) => {
    socket.setTimeout(2_000, () => socket.destroy());
    let frame = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => {
      frame += chunk;
      if (Buffer.byteLength(frame, 'utf8') > maximumFrameBytes) {
        denied += 1;
        socket.end('{"status":"denied"}\n');
        return;
      }
      const newline = frame.indexOf('\n');
      if (newline < 0) {
        return;
      }

      let request;
      try {
        request = JSON.parse(frame.slice(0, newline));
      } catch {
        denied += 1;
        socket.end('{"status":"denied"}\n');
        return;
      }

      const authorized =
        request?.version === 1 &&
        typeof request.token === 'string' &&
        typeof request.profileId === 'string' &&
        fixedTimeEqual(request.token, expectedToken) &&
        fixedTimeEqual(request.profileId, expectedProfile);
      if (authorized) {
        accepted += 1;
        socket.end('{"status":"accepted"}\n');
      } else {
        denied += 1;
        socket.end('{"status":"denied"}\n');
      }
    });
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(endpoint, resolve);
  });

  if (process.platform !== 'win32') {
    await chmod(root, 0o700);
    await chmod(endpoint, 0o600);
    const rootMode = (await stat(root)).mode & 0o777;
    const socketMode = (await stat(endpoint)).mode & 0o777;
    if (rootMode !== 0o700 || socketMode !== 0o600) {
      throw new Error('Unix adapter endpoint permissions are not owner-only.');
    }
  }

  return {
    endpoint,
    counts() {
      return { accepted, denied };
    },
    async close() {
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
      if (process.platform !== 'win32') {
        await rm(endpoint, { force: true });
      }
    },
  };
}

async function runProbe(binaryPath, endpoint, token, profile) {
  return runProcess(binaryPath, [], {
    env: {
      ...process.env,
      KONCLAVE_ADAPTER_ENDPOINT: endpoint,
      KONCLAVE_ADAPTER_TOKEN: token,
      KONCLAVE_PROFILE_ID: profile,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

async function runNodeProbe(endpoint, token, profile) {
  return new Promise((resolve) => {
    const socket = createConnection(endpoint);
    let settled = false;
    let response = '';
    const finish = (code) => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      resolve({ code, stdout: '', stderr: '' });
    };

    socket.setEncoding('utf8');
    socket.setTimeout(3_000, () => finish(1));
    socket.on('error', () => finish(1));
    socket.on('connect', () => {
      socket.write(`${JSON.stringify({ version: 1, profileId: profile, token })}\n`);
    });
    socket.on('data', (chunk) => {
      response += chunk;
      if (Buffer.byteLength(response, 'utf8') > maximumFrameBytes) {
        finish(1);
        return;
      }
      if (response.includes('\n')) {
        finish(response.trimEnd() === '{"status":"accepted"}' ? 0 : 2);
      }
    });
  });
}

function probeRunner(clientKind, binaryPath) {
  if (clientKind === 'rust') {
    return (endpoint, token, profile) => runProbe(binaryPath, endpoint, token, profile);
  }
  if (clientKind === 'node') {
    return runNodeProbe;
  }
  throw new Error('KONCLAVE_ADAPTER_PROBE_CLIENT must be rust or node.');
}

function requireExit(result, expected, scenario) {
  if (result.code !== expected) {
    throw new Error(
      `${scenario} returned ${String(result.code)} instead of ${String(expected)}: ${result.stderr
        .trim()
        .slice(0, 512)}`,
    );
  }
}

async function main() {
  const clientKind = process.env.KONCLAVE_ADAPTER_PROBE_CLIENT ?? 'rust';
  const buildRoot = await mkdtemp(join(tmpdir(), 'konclave-adapter-transport-'));
  const binaryPath = join(
    buildRoot,
    process.platform === 'win32' ? 'adapter_transport_probe.exe' : 'adapter_transport_probe',
  );

  try {
    if (clientKind === 'rust') {
      await compileProbe(binaryPath);
    }
    const executeProbe = probeRunner(clientKind, binaryPath);

    const firstToken = capability();
    const firstServer = await startAdapterServer(buildRoot, firstToken, profileId);
    requireExit(
      await executeProbe(firstServer.endpoint, firstToken, profileId),
      0,
      'authorized connection',
    );
    requireExit(
      await executeProbe(firstServer.endpoint, capability(), profileId),
      2,
      'wrong capability',
    );
    requireExit(
      await executeProbe(firstServer.endpoint, firstToken, 'other-profile'),
      2,
      'wrong profile',
    );
    requireExit(
      await executeProbe(firstServer.endpoint, firstToken, profileId),
      0,
      'daemon reconnect',
    );
    const firstCounts = firstServer.counts();
    await firstServer.close();
    requireExit(
      await executeProbe(firstServer.endpoint, firstToken, profileId),
      1,
      'stale endpoint',
    );

    const secondToken = capability();
    const secondServer = await startAdapterServer(buildRoot, secondToken, profileId);
    requireExit(
      await executeProbe(secondServer.endpoint, secondToken, profileId),
      0,
      'adapter restart',
    );
    const secondCounts = secondServer.counts();
    await secondServer.close();

    if (
      firstCounts.accepted !== 2 ||
      firstCounts.denied !== 2 ||
      secondCounts.accepted !== 1 ||
      secondCounts.denied !== 0
    ) {
      throw new Error('Adapter authorization counts did not match the exercised scenarios.');
    }

    console.log(
      `adapter-transport-probe (${clientKind}): accepted reconnects; denied wrong capability and profile; recovered after adapter restart.`,
    );
  } finally {
    await rm(buildRoot, { recursive: true, force: true });
  }
}

await main().catch((error) => {
  const message = error instanceof Error ? error.message : 'unknown failure';
  console.error(`adapter-transport-probe: ${message.slice(0, 512)}`);
  process.exitCode = 1;
});
