import { createHash } from 'node:crypto';
import { types } from 'node:util';

import { assertCanonicalProfile } from '../service/transcript.js';
import {
  decodeRecipeData,
  decodeRecipeDefinition,
  isRecipeHex,
  measureRecipeText,
  recipeDataProperty,
  RecipeDefinitionError,
  recipeDefinitionLimits,
  requireRecipeRecord,
  type RecipeDefinition,
} from './definition.js';

/** Fixed limits on selected effects and confidential in-memory run data. */
export const recipeRunLimits = Object.freeze({
  bindings: 16,
  inputBytes: 48 * 1024,
  encodedBytes: 256 * 1024,
});

/** Finite run refusals; source, input, identifiers and responses are never in errors. */
export type RecipeRunErrorCode =
  | 'invalid_run'
  | 'invalid_profile'
  | 'invalid_nonce'
  | 'invalid_binding'
  | 'duplicate_binding'
  | 'invalid_input'
  | 'run_too_large'
  | 'run_mismatch'
  | 'unknown_binding'
  | 'profile_mismatch'
  | 'invalid_response'
  | 'invalid_request'
  | 'unsupported_provider'
  | 'busy'
  | 'slot_conflict'
  | 'request_not_submitted';

/** A bounded refusal, not evidence that a submitted remote effect was canceled. */
export class RecipeRunError extends Error {
  constructor(readonly code: RecipeRunErrorCode) {
    super(`Recipe run rejected: ${code}`);
    this.name = 'RecipeRunError';
  }
}

/**
 * One explicitly selected logical request slot, not a membership or permission grant.
 * Repeated targets are allowed under different names; each name owns one message ID.
 */
export interface RecipeBinding {
  readonly name: string;
  readonly conversationId: string;
  readonly targetDeviceId: string;
}

/**
 * Confidential immutable application data. This value does not prove local approval.
 * Never log or persist it unprotected; this SDK performs no persistence.
 */
export interface RecipeRun {
  readonly definition: RecipeDefinition;
  readonly profile: string;
  readonly nonce: string;
  readonly bindings: readonly RecipeBinding[];
  readonly input: string;
  readonly canonicalJson: string;
  readonly runId: string;
}

const runDomain = 'konclave.recipe-run.v1\0';
const selectionFields = ['profile', 'nonce', 'bindings', 'input'];
const runFields = ['definition', 'definitionDigest', ...selectionFields];
const bindingFields = ['name', 'conversationId', 'targetDeviceId'];
const bindingNamePattern = /^[a-z0-9]+(?:[-_.][a-z0-9]+)*$/u;

function data<T>(operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    if (error instanceof RecipeDefinitionError) {
      throw new RecipeRunError('invalid_run');
    }
    throw error;
  }
}

export function parseRecipeBinding(value: unknown): RecipeBinding {
  requireRecipeRecord(value, bindingFields);
  const name = recipeDataProperty(value, 'name');
  const conversationId = recipeDataProperty(value, 'conversationId');
  const targetDeviceId = recipeDataProperty(value, 'targetDeviceId');
  if (
    typeof name !== 'string' ||
    name.length > 64 ||
    bindingNamePattern.exec(name)?.[0] !== name ||
    !isRecipeHex(conversationId, 64) ||
    !isRecipeHex(targetDeviceId, 64)
  ) {
    throw new RecipeRunError('invalid_binding');
  }
  return Object.freeze({ name, conversationId, targetDeviceId });
}

/**
 * Selects a new immutable run from independently pinned definition bytes and explicit data.
 * Selection has exactly profile, nonce, bindings and input. A new intent uses a fresh
 * 16-byte hexadecimal nonce; recovery instead decodes the original descriptor/run ID.
 * This function does not approve, execute, discover, pair or change any policy.
 * @throws {RecipeDefinitionError} If the selected definition cannot be authenticated.
 * @throws {RecipeRunError} If run data or a bound is invalid.
 */
export function createRecipeRun(
  definitionBytes: unknown,
  expectedDefinitionDigest: unknown,
  selection: unknown,
): RecipeRun {
  const definition = decodeRecipeDefinition(definitionBytes, expectedDefinitionDigest);
  return data(() => {
    requireRecipeRecord(selection, selectionFields);
    const profile = recipeDataProperty(selection, 'profile');
    const nonce = recipeDataProperty(selection, 'nonce');
    const selectedBindings = recipeDataProperty(selection, 'bindings');
    const input = recipeDataProperty(selection, 'input');
    if (typeof profile !== 'string') {
      throw new RecipeRunError('invalid_profile');
    }
    try {
      assertCanonicalProfile(profile);
    } catch {
      throw new RecipeRunError('invalid_profile');
    }
    if (!isRecipeHex(nonce, 32)) {
      throw new RecipeRunError('invalid_nonce');
    }
    if (
      types.isProxy(selectedBindings) ||
      !Array.isArray(selectedBindings) ||
      selectedBindings.length < 1 ||
      selectedBindings.length > recipeRunLimits.bindings
    ) {
      throw new RecipeRunError('invalid_binding');
    }
    if (Reflect.ownKeys(selectedBindings).length !== selectedBindings.length + 1) {
      throw new RecipeRunError('invalid_binding');
    }
    const names = new Set<string>();
    const bindings: RecipeBinding[] = [];
    for (let index = 0; index < selectedBindings.length; index += 1) {
      const selected = parseRecipeBinding(recipeDataProperty(selectedBindings, String(index)));
      if (names.has(selected.name)) {
        throw new RecipeRunError('duplicate_binding');
      }
      names.add(selected.name);
      bindings.push(selected);
    }
    if (typeof input !== 'string') {
      throw new RecipeRunError('invalid_input');
    }
    let inputJsonBytes: number;
    try {
      inputJsonBytes = measureRecipeText(input, recipeRunLimits.inputBytes);
    } catch (error) {
      if (error instanceof RecipeDefinitionError) {
        throw new RecipeRunError('invalid_input');
      }
      throw error;
    }
    const definitionJsonBytes = measureRecipeText(
      definition.canonicalJson,
      recipeDefinitionLimits.encodedBytes,
    );
    const empty = JSON.stringify({
      definition: '',
      definitionDigest: definition.digest,
      profile,
      nonce,
      bindings,
      input: '',
    });
    if (
      Buffer.byteLength(empty, 'utf8') + definitionJsonBytes + inputJsonBytes - 4 >
      recipeRunLimits.encodedBytes
    ) {
      throw new RecipeRunError('run_too_large');
    }
    const canonicalJson = JSON.stringify({
      definition: definition.canonicalJson,
      definitionDigest: definition.digest,
      profile,
      nonce,
      bindings,
      input,
    });
    const runId = createHash('sha256')
      .update(runDomain)
      .update(canonicalJson, 'utf8')
      .digest('hex');
    return Object.freeze({
      definition,
      profile,
      nonce,
      bindings: Object.freeze(bindings),
      input,
      canonicalJson,
      runId,
    });
  });
}

/**
 * Restores only an exact previously selected descriptor; missing data is not reconstructed.
 * Its canonical JSON may contain confidential input and must come from caller-owned custody.
 * @throws {RecipeRunError} If bytes, shape, bindings, bounds or the exact selection differ.
 */
export function decodeRecipeRun(bytes: unknown, expectedRunId: unknown): RecipeRun {
  if (!isRecipeHex(expectedRunId, 64)) {
    throw new RecipeRunError('run_mismatch');
  }
  return data(() => {
    const decoded = decodeRecipeData(bytes, recipeRunLimits.encodedBytes, 3, 18, 64);
    requireRecipeRecord(decoded.value, runFields);
    const definition = recipeDataProperty(decoded.value, 'definition');
    const definitionDigest = recipeDataProperty(decoded.value, 'definitionDigest');
    if (typeof definition !== 'string') {
      throw new RecipeRunError('invalid_run');
    }
    measureRecipeText(definition, recipeDefinitionLimits.encodedBytes);
    const run = createRecipeRun(Buffer.from(definition, 'utf8'), definitionDigest, {
      profile: recipeDataProperty(decoded.value, 'profile'),
      nonce: recipeDataProperty(decoded.value, 'nonce'),
      bindings: recipeDataProperty(decoded.value, 'bindings'),
      input: recipeDataProperty(decoded.value, 'input'),
    });
    if (
      run.runId !== expectedRunId ||
      !Buffer.from(run.canonicalJson, 'utf8').equals(decoded.bytes)
    ) {
      throw new RecipeRunError('run_mismatch');
    }
    return run;
  });
}

/**
 * Derives one stable application message ID for a selected slot using its exact run identity.
 * It grants no permission and contains no raw profile, participant or input value.
 * @throws {RecipeRunError} If the slot was not included in the selected descriptor.
 */
export function recipeMessageId(run: RecipeRun, bindingName: string): string {
  if (!run.bindings.some((item) => item.name === bindingName)) {
    throw new RecipeRunError('unknown_binding');
  }
  return createHash('sha256')
    .update('konclave.recipe-message.v1\0')
    .update(Buffer.from(run.runId, 'hex'))
    .update(bindingName, 'utf8')
    .digest()
    .subarray(0, 16)
    .toString('hex');
}
