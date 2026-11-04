import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { format } from 'prettier';
import { describe, expect, it } from 'vitest';

import contracts from '../../../fixtures/local-service/v1/copilot-tools.json';
import { createKonclaveCommands } from '../src/service/commands.js';
import type { LocalServiceClient } from '../src/service/client.js';
import { konclaveTools } from '../src/service/tools.js';
import { isRecord } from '../src/service/validation.js';

const root = new URL('../../../', import.meta.url);
const generate = process.env.KONCLAVE_GENERATE_REFERENCE === '1';

function cell(value: string): string {
  return value.replaceAll('|', '\\|').replaceAll('\n', ' ');
}

function schemaType(value: unknown): string {
  if (!isRecord(value)) throw new Error('Invalid generated field schema');
  if (value.const !== undefined) return JSON.stringify(value.const);
  if (typeof value.$ref === 'string') return value.$ref.split('/').at(-1) ?? value.$ref;
  if (Array.isArray(value.enum)) return value.enum.map(String).join(' / ');
  if (Array.isArray(value.anyOf)) return value.anyOf.map(schemaType).join(' / ');
  if (value.type === 'array') return `${schemaType(value.items)}[]`;
  if (Array.isArray(value.type)) return value.type.map(String).join(' / ');
  if (typeof value.type === 'string') return value.type;
  return 'See full schema';
}

function resultDetails(schema: unknown): string {
  if (!isRecord(schema)) throw new Error('Invalid generated result schema');
  const definitions = schema.$defs;
  if (definitions === undefined) return '';
  if (!isRecord(definitions)) throw new Error('Invalid generated result definitions');
  return Object.entries(definitions)
    .map(([name, definition]) => {
      if (!isRecord(definition)) throw new Error(`Invalid result definition: ${name}`);
      const variants = definition.oneOf;
      if (variants !== undefined && !Array.isArray(variants)) {
        throw new Error(`Invalid result variants: ${name}`);
      }
      return [
        `#### ${name}`,
        '',
        definition.properties === undefined ? '' : fields(definition, true),
        ...(variants ?? []).map(
          (variant, index) => `##### Variant ${index + 1}\n\n${fields(variant, false)}`,
        ),
      ].join('\n');
    })
    .join('\n');
}

function fields(schema: unknown, requireDescriptions: boolean): string {
  if (!isRecord(schema) || !isRecord(schema.properties)) {
    throw new Error('Invalid generated object schema');
  }
  const required = schema.required;
  if (required !== undefined && !Array.isArray(required)) {
    throw new Error('Invalid generated required fields');
  }
  const rows = Object.entries(schema.properties).map(([name, value]) => {
    if (!isRecord(value)) throw new Error(`Invalid schema for ${name}`);
    const description = typeof value.description === 'string' ? value.description : '';
    if (requireDescriptions && description.length === 0) {
      throw new Error(`Missing authored input documentation: ${name}`);
    }
    return `| \`${name}\` | ${cell(schemaType(value))} | ${required?.includes(name) ? 'yes' : 'no'} | ${cell(description)} |`;
  });
  return rows.length === 0
    ? 'No fields.\n'
    : ['| Field | Type | Required | Meaning |', '| --- | --- | --- | --- |', ...rows, ''].join(
        '\n',
      );
}

async function checkPage(path: string, expected: string): Promise<void> {
  const url = new URL(path, root);
  const markdown = await format(expected, { parser: 'markdown' });
  if (generate) await writeFile(url, markdown);
  expect(await readFile(url, 'utf8'), fileURLToPath(url)).toBe(markdown);
}

describe('reader-facing contract views', () => {
  it('publishes the same typed workspace example that the normal typecheck compiles', async () => {
    const example = await readFile(
      new URL('extensions/Konclave.HostExtension/tests/examples/installed-client.ts', root),
      'utf8',
    );
    const path = 'docs/integrations/typescript-client.md';
    const original = await readFile(new URL(path, root), 'utf8');
    const start = '<!-- installed-client-example:start -->';
    const end = '<!-- installed-client-example:end -->';
    const begin = original.indexOf(start);
    const finish = original.indexOf(end);
    if (begin < 0 || finish <= begin) throw new Error('Typed example markers are missing');
    await checkPage(
      path,
      original.slice(0, begin + start.length) +
        '\n\n```typescript\n' +
        example.trimEnd() +
        '\n```\n\n' +
        original.slice(finish),
    );
  });

  it('publishes the projected agent inputs and native result fields without a second registry', async () => {
    const sections = konclaveTools.map((tool) => {
      const contract = contracts.find((candidate) => candidate.name === tool.name);
      if (!contract) throw new Error(`Missing native result schema for ${tool.name}`);
      return [
        `## ${tool.name}`,
        '',
        tool.description,
        '',
        '### Inputs',
        '',
        fields(tool.parameters, true),
        '### Result',
        '',
        fields(contract.outputSchema, true),
        resultDetails(contract.outputSchema),
      ].join('\n');
    });
    await checkPage(
      'docs/reference/agent-tool-contracts.md',
      [
        '# Agent-tool field reference',
        '',
        '<!-- Generated by tests/documentation.test.ts from the native fixture and production projection. Do not edit. -->',
        '',
        'Read [tool workflows and shared result semantics](agent-tools.md) first.',
        'Types name JSON Schema definitions in the [full native fixture](../../fixtures/local-service/v1/copilot-tools.json).',
        'Optional fields may be nullable; follow their field semantics. A schema is not an authorization grant.',
        '',
        ...sections,
      ].join('\n'),
    );
  });

  it('keeps the published command inventory equal to actual deterministic help', async () => {
    const lines: string[] = [];
    const client: LocalServiceClient = {
      profile: 'documentation',
      connected: false,
      request: async () => {
        throw new Error('Help must not contact a service');
      },
      retire: async () => {},
      close() {},
    };
    const command = createKonclaveCommands({
      client,
      output: { write: (line) => void lines.push(line) },
    }).find((candidate) => candidate.name === 'konclave');
    if (!command) throw new Error('Konclave command is missing');
    await command.handler({
      args: 'help',
      command: '/konclave help',
      commandName: 'konclave',
      sessionId: 'documentation',
    });
    expect(lines[0]).toBe('Konclave commands (deterministic; no model inference):');
    const path = 'extensions/Konclave.HostExtension/docs/copilot-cli-extension.md';
    const original = await readFile(new URL(path, root), 'utf8');
    const start = '<!-- command-reference:start -->';
    const end = '<!-- command-reference:end -->';
    const begin = original.indexOf(start);
    const finish = original.indexOf(end);
    if (begin < 0 || finish <= begin) throw new Error('Command reference markers are missing');
    await checkPage(
      path,
      original.slice(0, begin + start.length) +
        '\n\n```text\n' +
        lines.join('\n') +
        '\n```\n\n' +
        original.slice(finish),
    );
  });
});
