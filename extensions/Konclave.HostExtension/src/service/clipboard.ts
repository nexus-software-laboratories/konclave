import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';

const clipboardTimeoutMilliseconds = 5_000;
const maximumClipboardBytes = 512;
const maximumProcessOutputBytes = 4 * 1024;

type ClipboardCommandRunner = (
  file: string,
  args: readonly string[],
  input: string,
) => Promise<boolean>;

export interface PairingClipboard {
  writeToken(token: string): Promise<ClipboardWriteResult>;
  clear(): Promise<boolean>;
}

export interface ClipboardWriteResult {
  readonly copied: boolean;
  readonly mayContainToken: boolean;
}

interface ClipboardCommand {
  readonly file: string;
  readonly args: readonly string[];
}

function windowsClipboardCommand(): ClipboardCommand {
  return {
    file: 'powershell.exe',
    args: [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      '$value = [Console]::In.ReadToEnd(); Set-Clipboard -Value $value',
    ],
  };
}

function writeCommands(
  platform: NodeJS.Platform,
  environment: NodeJS.ProcessEnv,
): ClipboardCommand[] {
  switch (platform) {
    case 'win32':
      return [windowsClipboardCommand()];
    case 'darwin':
      return [{ file: 'pbcopy', args: [] }];
    case 'linux': {
      const commands: ClipboardCommand[] = [];
      if (environment.WAYLAND_DISPLAY) {
        commands.push({ file: 'wl-copy', args: ['--type', 'text/plain'] });
      }
      if (environment.DISPLAY) {
        commands.push({ file: 'xclip', args: ['-selection', 'clipboard', '-in'] });
      }
      return commands;
    }
    default:
      return [];
  }
}

function clearCommands(
  platform: NodeJS.Platform,
  environment: NodeJS.ProcessEnv,
): ClipboardCommand[] {
  if (platform === 'linux' && environment.WAYLAND_DISPLAY) {
    return [{ file: 'wl-copy', args: ['--clear'] }, ...writeCommands(platform, environment)];
  }
  return writeCommands(platform, environment);
}

async function tryCommands(
  commands: readonly ClipboardCommand[],
  input: string,
  run: ClipboardCommandRunner,
): Promise<ClipboardWriteResult> {
  if (commands.length === 0) {
    return { copied: false, mayContainToken: false };
  }
  for (const command of commands) {
    if (await run(command.file, command.args, input)) {
      return { copied: true, mayContainToken: true };
    }
  }
  return { copied: false, mayContainToken: true };
}

async function runClipboardCommand(
  file: string,
  args: readonly string[],
  input: string,
): Promise<boolean> {
  const inputBytes = Buffer.from(input, 'utf8');
  if (inputBytes.length > maximumClipboardBytes) {
    inputBytes.fill(0);
    return false;
  }
  return new Promise<boolean>((resolve) => {
    let child: ChildProcessWithoutNullStreams;
    try {
      child = spawn(file, args, {
        shell: false,
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      });
    } catch {
      inputBytes.fill(0);
      resolve(false);
      return;
    }

    let settled = false;
    let outputBytes = 0;
    const finish = (success: boolean) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      inputBytes.fill(0);
      resolve(success);
    };
    const observeOutput = (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes > maximumProcessOutputBytes) {
        child.kill();
        finish(false);
      }
    };
    const timer = setTimeout(() => {
      child.kill();
      finish(false);
    }, clipboardTimeoutMilliseconds);

    child.stdout.on('data', observeOutput);
    child.stderr.on('data', observeOutput);
    child.on('error', () => finish(false));
    child.on('close', (code) => finish(code === 0 && outputBytes <= maximumProcessOutputBytes));
    child.stdin.on('error', () => finish(false));
    child.stdin.end(inputBytes);
  });
}

/** Creates a bounded native clipboard adapter with no shell interpolation. */
export function createPairingClipboard(
  platform: NodeJS.Platform = process.platform,
  environment: NodeJS.ProcessEnv = process.env,
  run: ClipboardCommandRunner = runClipboardCommand,
): PairingClipboard {
  return {
    writeToken(token) {
      return tryCommands(writeCommands(platform, environment), token, run);
    },
    async clear() {
      return (await tryCommands(clearCommands(platform, environment), '', run)).copied;
    },
  };
}
