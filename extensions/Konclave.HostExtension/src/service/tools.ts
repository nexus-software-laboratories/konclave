import { createHash } from 'node:crypto';

import type { Tool, ToolInvocation } from '@github/copilot-sdk';

import generatedToolContracts from '../../../../fixtures/local-service/v1/copilot-tools.json';

import { collaborationAuthorizationArgument } from '../collaboration-contract.js';
import type { LocalServiceClient } from './client.js';
import type { ToolOperation } from './operations.js';

/**
 * Agent tools registered directly with the Copilot SDK over the shared client.
 *
 * Rust's MCP router generates the versioned fixture consumed here, including every
 * name, description, and input/output schema. A Rust staleness test compares that
 * fixture with the live router, while the TypeScript test compares its finite names
 * with `toolOperations`. The assertion below is therefore confined to the generated
 * cross-language boundary TypeScript cannot infer from JSON.
 */

interface GeneratedToolContract {
  readonly name: ToolOperation;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
  readonly outputSchema: Record<string, unknown>;
}

const toolContracts = generatedToolContracts as readonly GeneratedToolContract[];
const hookInjectedArguments: Partial<Record<ToolOperation, ReadonlySet<string>>> = {
  send_message: new Set([collaborationAuthorizationArgument]),
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function agentVisibleInputSchema(contract: GeneratedToolContract): Record<string, unknown> {
  const injected = hookInjectedArguments[contract.name];
  if (!injected) {
    return contract.inputSchema;
  }
  const properties = contract.inputSchema.properties;
  const required = contract.inputSchema.required;
  if (!isRecord(properties) || (required !== undefined && !isStringArray(required))) {
    throw new Error(`Generated ${contract.name} tool schema is malformed.`);
  }
  return {
    ...contract.inputSchema,
    properties: Object.fromEntries(
      Object.entries(properties).filter(([name]) => !injected.has(name)),
    ),
    ...(required === undefined
      ? {}
      : { required: required.filter((name) => !injected.has(name)) }),
  };
}

export interface KonclaveToolDefinition {
  readonly name: ToolOperation;
  readonly description: string;
  readonly parameters: Record<string, unknown>;
}

/** The closed agent tool table generated from the service router. */
export const konclaveTools: readonly KonclaveToolDefinition[] = toolContracts.map((contract) => ({
  name: contract.name,
  description: contract.description,
  parameters: agentVisibleInputSchema(contract),
}));

/** The exact SDK tool shape this extension registers. */
export interface RegisteredTool extends Tool<unknown> {
  readonly description: string;
  readonly parameters: Record<string, unknown>;
  handler(args: unknown, invocation?: ToolInvocation): Promise<unknown>;
}

export interface ToolRegistrationOptions {
  readonly client: LocalServiceClient;
  readonly toolDeadlineMs?: number;
}

const defaultToolDeadlineMs = 90_000;
const toolRequestIdDomain = 'konclave:copilot-tool-request:1\0';
const maxInvocationIdentifierBytes = 1_024;

function toolRequestId(invocation: ToolInvocation): Buffer {
  const sessionBytes = Buffer.byteLength(invocation.sessionId, 'utf8');
  const toolCallBytes = Buffer.byteLength(invocation.toolCallId, 'utf8');
  if (
    sessionBytes === 0 ||
    sessionBytes > maxInvocationIdentifierBytes ||
    toolCallBytes === 0 ||
    toolCallBytes > maxInvocationIdentifierBytes
  ) {
    throw new Error('Copilot tool invocation identifiers are invalid.');
  }
  return createHash('sha256')
    .update(toolRequestIdDomain)
    .update(Buffer.from([sessionBytes >> 8, sessionBytes & 0xff]))
    .update(invocation.sessionId)
    .update(Buffer.from([toolCallBytes >> 8, toolCallBytes & 0xff]))
    .update(invocation.toolCallId)
    .digest()
    .subarray(0, 16);
}

/**
 * Builds the tool handlers that invoke the shared client.
 *
 * A handler forwards the SDK-validated arguments to the operation of the same name
 * and returns the service's structured result. The SDK session/tool-call identity is
 * domain-hashed into a stable idempotency key when available. No handler interprets
 * the result, so the agent-visible contract remains the service contract.
 */
export function createKonclaveTools(options: ToolRegistrationOptions): RegisteredTool[] {
  const deadline = options.toolDeadlineMs ?? defaultToolDeadlineMs;

  return konclaveTools.map((definition) => ({
    name: definition.name,
    description: definition.description,
    parameters: definition.parameters,
    async handler(args: unknown, invocation?: ToolInvocation) {
      return options.client.request(
        definition.name,
        args ?? {},
        invocation ? { deadlineMs: deadline, requestId: toolRequestId(invocation) } : deadline,
      );
    },
  }));
}
