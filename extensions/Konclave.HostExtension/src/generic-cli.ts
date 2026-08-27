import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  genericCommandFailure,
  invokeGenericCommand,
  parseGenericCommandArguments,
} from './generic-command.js';

const maxInputBytes = 1_048_576;

async function readPayload(): Promise<unknown> {
  if (process.stdin.isTTY) {
    return {};
  }
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;
    if (length > maxInputBytes) {
      throw new Error('payload_too_large');
    }
    chunks.push(bytes);
  }
  if (length === 0) {
    return {};
  }
  return JSON.parse(Buffer.concat(chunks, length).toString('utf8')) as unknown;
}

async function run(): Promise<void> {
  const args = parseGenericCommandArguments(process.argv.slice(2));
  const payload = await readPayload();
  const controller = new AbortController();
  const abort = () => controller.abort();
  process.once('SIGINT', abort);
  process.once('SIGTERM', abort);
  const moduleDir = dirname(fileURLToPath(import.meta.url));
  try {
    const result = await invokeGenericCommand(args, payload, {
      environment: process.env,
      moduleDir,
      signal: controller.signal,
      reportCleanupFailure: () => {
        process.stderr.write('{"warning":"grant_retirement_failed"}\n');
      },
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    process.off('SIGINT', abort);
    process.off('SIGTERM', abort);
  }
}

void run().catch((error: unknown) => {
  process.stderr.write(`${JSON.stringify(genericCommandFailure(error))}\n`);
  process.exitCode = 1;
});
