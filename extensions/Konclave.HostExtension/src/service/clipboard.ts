import { spawn } from 'node:child_process';

const clipboardTimeoutMilliseconds = 5_000;
const maximumClipboardBytes = 512;
const maximumProcessOutputBytes = 4 * 1024;

export type ClipboardCommandOutcome = 'success' | 'unavailable' | 'indeterminate';
export type ClipboardProviderId = 'windows' | 'macos' | 'wayland' | 'x11';

export type ClipboardCommandRunner = (
  file: string,
  args: readonly string[],
  input: string,
) => Promise<ClipboardCommandOutcome>;

export interface ClipboardProcess {
  readonly stdin: {
    on(event: 'error', listener: () => void): unknown;
    end(input: Uint8Array): unknown;
  };
  readonly stdout: {
    on(event: 'data', listener: (chunk: Buffer) => void): unknown;
  };
  readonly stderr: {
    on(event: 'data', listener: (chunk: Buffer) => void): unknown;
  };
  on(event: 'spawn' | 'error', listener: () => void): unknown;
  on(event: 'close', listener: (code: number | null) => void): unknown;
  kill(signal: 'SIGKILL'): boolean;
}

export type ClipboardProcessSpawner = (file: string, args: readonly string[]) => ClipboardProcess;

export interface PairingClipboard {
  writeToken(token: string): Promise<ClipboardWriteReceipt>;
  clear(receipt: ClipboardWriteReceipt): Promise<boolean>;
}

export interface ClipboardWriteReceipt {
  readonly copied: boolean;
  readonly providers: readonly ClipboardProviderId[];
}

interface ClipboardCommand {
  readonly provider: ClipboardProviderId;
  readonly file: string;
  readonly args: readonly string[];
}

const providerCommands: Readonly<Record<ClipboardProviderId, ClipboardCommand>> = {
  windows: {
    provider: 'windows',
    file: String.raw`C:\Windows\System32\clip.exe`,
    args: [],
  },
  macos: {
    provider: 'macos',
    file: '/usr/bin/pbcopy',
    args: [],
  },
  wayland: {
    provider: 'wayland',
    file: '/usr/bin/wl-copy',
    args: ['--type', 'text/plain'],
  },
  x11: {
    provider: 'x11',
    file: '/usr/bin/xclip',
    args: ['-selection', 'clipboard', '-in'],
  },
};

function writeCommands(
  platform: NodeJS.Platform,
  environment: NodeJS.ProcessEnv,
): ClipboardCommand[] {
  switch (platform) {
    case 'win32':
      return [providerCommands.windows];
    case 'darwin':
      return [providerCommands.macos];
    case 'linux': {
      const commands: ClipboardCommand[] = [];
      if (environment.WAYLAND_DISPLAY) {
        commands.push(providerCommands.wayland);
      }
      if (environment.DISPLAY) {
        commands.push(providerCommands.x11);
      }
      return commands;
    }
    default:
      return [];
  }
}

function clearCommand(provider: ClipboardProviderId): ClipboardCommand {
  if (provider === 'wayland') {
    return {
      provider,
      file: providerCommands.wayland.file,
      args: ['--clear'],
    };
  }
  return providerCommands[provider];
}

async function writeWithProviders(
  commands: readonly ClipboardCommand[],
  input: string,
  run: ClipboardCommandRunner,
): Promise<ClipboardWriteReceipt> {
  const providers: ClipboardProviderId[] = [];
  for (const command of commands) {
    const outcome = await run(command.file, command.args, input);
    if (outcome !== 'unavailable') {
      providers.push(command.provider);
    }
    if (outcome === 'success') {
      return { copied: true, providers };
    }
  }
  return { copied: false, providers };
}

async function clearProviders(
  providers: readonly ClipboardProviderId[],
  run: ClipboardCommandRunner,
): Promise<boolean> {
  if (providers.length === 0) {
    return false;
  }
  let cleared = true;
  for (const provider of new Set(providers)) {
    const command = clearCommand(provider);
    if ((await run(command.file, command.args, '')) !== 'success') {
      cleared = false;
    }
  }
  return cleared;
}

function spawnClipboardProcess(file: string, args: readonly string[]): ClipboardProcess {
  return spawn(file, args, {
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });
}

/** @internal Executes one fixed clipboard provider under hard I/O bounds. */
export async function runClipboardCommand(
  file: string,
  args: readonly string[],
  input: string,
  spawnProcess: ClipboardProcessSpawner = spawnClipboardProcess,
): Promise<ClipboardCommandOutcome> {
  const inputBytes = Buffer.from(input, 'utf8');
  if (inputBytes.length > maximumClipboardBytes) {
    inputBytes.fill(0);
    return 'unavailable';
  }
  return new Promise<ClipboardCommandOutcome>((resolve) => {
    let child: ClipboardProcess;
    try {
      child = spawnProcess(file, args);
    } catch {
      inputBytes.fill(0);
      resolve('unavailable');
      return;
    }

    let settled = false;
    let spawned = false;
    let forcedIndeterminate = false;
    let outputBytes = 0;
    const finish = (outcome: ClipboardCommandOutcome) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      inputBytes.fill(0);
      resolve(outcome);
    };
    const terminate = () => {
      if (forcedIndeterminate) {
        return;
      }
      forcedIndeterminate = true;
      child.kill('SIGKILL');
    };
    const observeOutput = (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes > maximumProcessOutputBytes) {
        terminate();
      }
    };
    const timer = setTimeout(terminate, clipboardTimeoutMilliseconds);

    child.stdout.on('data', observeOutput);
    child.stderr.on('data', observeOutput);
    child.on('spawn', () => {
      spawned = true;
    });
    child.on('error', () => {
      if (spawned) {
        forcedIndeterminate = true;
      } else {
        finish('unavailable');
      }
    });
    child.on('close', (code) => {
      finish(
        !forcedIndeterminate && code === 0 && outputBytes <= maximumProcessOutputBytes
          ? 'success'
          : 'indeterminate',
      );
    });
    child.stdin.on('error', terminate);
    child.stdin.end(inputBytes);
  });
}

/** Creates a bounded native clipboard adapter with fixed system executable paths. */
export function createPairingClipboard(
  platform: NodeJS.Platform = process.platform,
  environment: NodeJS.ProcessEnv = process.env,
  run: ClipboardCommandRunner = runClipboardCommand,
): PairingClipboard {
  return {
    writeToken(token) {
      return writeWithProviders(writeCommands(platform, environment), token, run);
    },
    clear(receipt) {
      return clearProviders(receipt.providers, run);
    },
  };
}
