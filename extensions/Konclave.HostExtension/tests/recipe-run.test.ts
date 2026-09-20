import { describe, expect, it, vi } from 'vitest';

import { createRecipeDefinition } from '../src/recipes/definition.js';
import {
  createRecipeRun,
  decodeRecipeRun,
  recipeMessageId,
  RecipeRunError,
  recipeRunLimits,
} from '../src/recipes/run.js';

const definition = createRecipeDefinition({
  name: 'example',
  provider: 'example.provider',
  configuration: 'Use the supplied context.',
});
const definitionBytes = Buffer.from(definition.canonicalJson);
const first = {
  name: 'first',
  conversationId: '01'.repeat(32),
  targetDeviceId: '02'.repeat(32),
};
const second = {
  name: 'second',
  conversationId: '03'.repeat(32),
  targetDeviceId: '04'.repeat(32),
};
const selection = {
  profile: 'recipe-test',
  nonce: '05'.repeat(16),
  bindings: [first, second],
  input: 'Confidential supplied context.',
};

describe('immutable external recipe runs', () => {
  it('restores exact selected data and stable per-slot identities', () => {
    const run = createRecipeRun(definitionBytes, definition.digest, selection);
    const restored = decodeRecipeRun(Buffer.from(run.canonicalJson), run.runId);
    expect(restored).toEqual(run);
    expect(recipeMessageId(restored, 'first')).toBe(recipeMessageId(run, 'first'));
    expect(recipeMessageId(run, 'first')).toMatch(/^[0-9a-f]{32}$/u);
    expect(recipeMessageId(run, 'first')).not.toBe(recipeMessageId(run, 'second'));
    expect(Object.isFrozen(run)).toBe(true);
    expect(Object.isFrozen(run.bindings)).toBe(true);
    expect(Object.isFrozen(run.bindings[0])).toBe(true);
    expect(() => recipeMessageId(run, 'undeclared')).toThrow('unknown_binding');
  });

  it('rejects changed selections rather than silently restoring different work', () => {
    const original = createRecipeRun(definitionBytes, definition.digest, selection);
    for (const changed of [
      { ...selection, profile: 'other-profile' },
      { ...selection, nonce: '06'.repeat(16) },
      { ...selection, input: 'changed context' },
      { ...selection, bindings: [second, first] },
      {
        ...selection,
        bindings: [{ ...first, conversationId: '07'.repeat(32) }, second],
      },
      {
        ...selection,
        bindings: [{ ...first, targetDeviceId: '08'.repeat(32) }, second],
      },
    ]) {
      const run = createRecipeRun(definitionBytes, definition.digest, changed);
      expect(run.runId).not.toBe(original.runId);
      expect(() => decodeRecipeRun(Buffer.from(run.canonicalJson), original.runId)).toThrow(
        'run_mismatch',
      );
    }
    const changedDefinition = createRecipeDefinition({
      name: definition.name,
      provider: definition.provider,
      configuration: 'A different exact definition.',
    });
    const run = createRecipeRun(
      Buffer.from(changedDefinition.canonicalJson),
      changedDefinition.digest,
      selection,
    );
    expect(() => decodeRecipeRun(Buffer.from(run.canonicalJson), original.runId)).toThrow(
      'run_mismatch',
    );
  });

  it('copies caller arrays and permits explicit repeated targets under distinct slots', () => {
    const binding = { ...first };
    const bindings = [binding, { ...first, name: 'again' }];
    const run = createRecipeRun(definitionBytes, definition.digest, { ...selection, bindings });
    binding.targetDeviceId = '09'.repeat(32);
    bindings.reverse();
    expect(run.bindings[0]).toEqual(first);
    expect(recipeMessageId(run, 'first')).not.toBe(recipeMessageId(run, 'again'));
  });

  it('rejects invalid profiles, nonces, bindings and input with finite errors', () => {
    for (const change of [
      { profile: 'UPPERCASE' },
      { profile: '../profile' },
      { profile: 1 },
      { nonce: 'invalid' },
      { nonce: 'AA'.repeat(16) },
      { bindings: [] },
      { bindings: {} },
      { bindings: [first, first] },
      { bindings: [{ ...first, name: '' }] },
      { bindings: [{ ...first, name: 'bad\n' }] },
      { bindings: [{ ...first, conversationId: 'bad' }] },
      { bindings: [{ ...first, targetDeviceId: 'AA'.repeat(32) }] },
      { bindings: [{ ...first, extra: true }] },
      { input: null },
      { input: '\ud800' },
      { input: 'x'.repeat(recipeRunLimits.inputBytes + 1) },
    ]) {
      expect(() =>
        createRecipeRun(definitionBytes, definition.digest, { ...selection, ...change }),
      ).toThrow(RecipeRunError);
    }
    expect(() =>
      createRecipeRun(definitionBytes, definition.digest, { ...selection, extra: true }),
    ).toThrow('invalid_run');
  });

  it('enforces exact slot capacity and rejects sparse or accessor arrays without calls', () => {
    const bindings = Array.from({ length: recipeRunLimits.bindings }, (_, index) => ({
      ...first,
      name: `slot-${index}`,
    }));
    const run = createRecipeRun(definitionBytes, definition.digest, { ...selection, bindings });
    expect(decodeRecipeRun(Buffer.from(run.canonicalJson), run.runId)).toEqual(run);
    expect(() =>
      createRecipeRun(definitionBytes, definition.digest, {
        ...selection,
        bindings: [...bindings, { ...first, name: 'extra' }],
      }),
    ).toThrow('invalid_binding');
    const getter = vi.fn(() => first);
    const accessors = [first];
    Object.defineProperty(accessors, '0', { get: getter });
    expect(() =>
      createRecipeRun(definitionBytes, definition.digest, { ...selection, bindings: accessors }),
    ).toThrow('invalid_run');
    expect(getter).not.toHaveBeenCalled();
    expect(() =>
      createRecipeRun(definitionBytes, definition.digest, { ...selection, bindings: Array(1) }),
    ).toThrow('invalid_binding');
  });

  it('keeps encoding and parse allocation bounded without a general workflow language', () => {
    expect(() =>
      createRecipeRun(definitionBytes, definition.digest, {
        ...selection,
        input: '\0'.repeat(recipeRunLimits.inputBytes),
      }),
    ).toThrow('run_too_large');
    const run = createRecipeRun(definitionBytes, definition.digest, selection);
    for (const text of [
      ` ${run.canonicalJson}`,
      run.canonicalJson.replace('"profile":', '"extra":'),
      '['.repeat(10_000),
      '{"bindings":[' + '0,'.repeat(1_000) + '0]}',
      '{"bindings":[' + '{},'.repeat(100) + '{}]}',
    ]) {
      expect(() => decodeRecipeRun(Buffer.from(text), run.runId)).toThrow(RecipeRunError);
    }
    expect(() =>
      decodeRecipeRun(new Uint8Array(recipeRunLimits.encodedBytes + 1), run.runId),
    ).toThrow('invalid_run');
    expect(() => decodeRecipeRun(Buffer.from(run.canonicalJson), 'invalid')).toThrow(
      'run_mismatch',
    );
  });
});
