import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';

const maximumDocumentBytes = 64 * 1024;
// Reserve time to submit completion before the service's challenge expires.
const helperTimeoutMilliseconds = 115_000;

/** Finite local native-helper failure that carries no provider output. */
export class NativeUserPresenceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NativeUserPresenceError';
  }
}

type SpawnHelper = (file: string, args: readonly string[]) => ChildProcessWithoutNullStreams;

function defaultSpawnHelper(file: string, args: readonly string[]): ChildProcessWithoutNullStreams {
  return spawn(file, args, {
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: false,
  });
}

/**
 * Runs the installed native WebAuthn helper without exposing a shell or its stderr.
 *
 * @throws {NativeUserPresenceError} When the platform, process, bounds, exit status,
 * or returned JSON is invalid.
 */
export function requestNativeUserPresence(
  helper: string,
  request: unknown,
  platform: NodeJS.Platform = process.platform,
  spawnHelper: SpawnHelper = defaultSpawnHelper,
): Promise<Record<string, unknown>> {
  if (platform !== 'win32') {
    throw new NativeUserPresenceError('Native user presence is unavailable on this platform.');
  }
  let input: Buffer;
  try {
    input = Buffer.from(JSON.stringify(request), 'utf8');
  } catch {
    throw new NativeUserPresenceError('Native user-presence request is invalid.');
  }
  if (input.length === 0 || input.length > maximumDocumentBytes) {
    throw new NativeUserPresenceError('Native user-presence request is invalid.');
  }

  return new Promise<Record<string, unknown>>((resolve, reject) => {
    let child: ChildProcessWithoutNullStreams;
    try {
      child = spawnHelper(helper, ['user-presence-helper', 'authenticate']);
    } catch {
      reject(new NativeUserPresenceError('Native user presence could not start.'));
      return;
    }
    const output: Buffer[] = [];
    let outputBytes = 0;
    let errorBytes = 0;
    let settled = false;
    const finish = (error: NativeUserPresenceError | null, value?: Record<string, unknown>) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      if (error === null && value !== undefined) {
        resolve(value);
      } else {
        reject(error ?? new NativeUserPresenceError('Native user presence failed.'));
      }
    };
    const stopForBounds = () => {
      child.kill();
      finish(new NativeUserPresenceError('Native user-presence response is invalid.'));
    };
    const timer = setTimeout(() => {
      child.kill();
      finish(new NativeUserPresenceError('Native user presence timed out.'));
    }, helperTimeoutMilliseconds);

    child.stdout.on('data', (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes > maximumDocumentBytes) {
        stopForBounds();
        return;
      }
      output.push(Buffer.from(chunk));
    });
    child.stderr.on('data', (chunk: Buffer) => {
      errorBytes += chunk.length;
      if (errorBytes > maximumDocumentBytes) {
        stopForBounds();
      }
    });
    child.on('error', () => {
      finish(new NativeUserPresenceError('Native user presence could not start.'));
    });
    child.on('close', (code) => {
      if (settled) {
        return;
      }
      if (code !== 0 || errorBytes > maximumDocumentBytes) {
        finish(new NativeUserPresenceError('Native user presence was not approved.'));
        return;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(Buffer.concat(output, outputBytes).toString('utf8'));
      } catch {
        finish(new NativeUserPresenceError('Native user-presence response is invalid.'));
        return;
      }
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        finish(new NativeUserPresenceError('Native user-presence response is invalid.'));
        return;
      }
      finish(null, parsed as Record<string, unknown>);
    });
    child.stdin.on('error', () => {
      finish(new NativeUserPresenceError('Native user presence could not receive its request.'));
    });
    child.stdin.end(input);
  });
}
