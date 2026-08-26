import type { Tool, ToolInvocation } from '@github/copilot-sdk';

import generatedToolContracts from '../../../../fixtures/local-service/v1/copilot-tools.json';

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

export interface KonclaveToolDefinition {
  readonly name: ToolOperation;
  readonly description: string;
  readonly parameters: Record<string, unknown>;
}

/** The closed agent tool table generated from the service router. */
export const konclaveTools: readonly KonclaveToolDefinition[] = toolContracts.map((contract) => ({
  name: contract.name,
  description: contract.description,
  parameters: contract.inputSchema,
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

/**
 * Builds the tool handlers that invoke the shared client.
 *
 * A handler forwards the SDK-validated arguments to the operation of the same name
 * and returns the service's structured result. No handler interprets that result, so
 * the agent-visible contract remains the service contract.
 */
export function createKonclaveTools(options: ToolRegistrationOptions): RegisteredTool[] {
  const deadline = options.toolDeadlineMs ?? defaultToolDeadlineMs;

  return konclaveTools.map((definition) => ({
    name: definition.name,
    description: definition.description,
    parameters: definition.parameters,
    async handler(args: unknown) {
      return options.client.request(definition.name, args ?? {}, deadline);
    },
  }));
}
