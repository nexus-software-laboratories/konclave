import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

import {
  createRecipeDefinition,
  decodeRecipeDefinition,
  RecipeDefinitionError,
  recipeDefinitionLimits,
  type RecipeDefinitionErrorCode,
} from '../src/recipes/definition.js';

const input = { name: 'sample', provider: 'local-provider', configuration: '' };
const canonicalJson = '{"name":"sample","provider":"local-provider","configuration":""}';
const fixtureDigest = '0abd07fad4a171daad202d6003ea2b6e919e90f877dbb294e9261f597540a58a';

function digest(text: string): string {
  return createHash('sha256')
    .update('konclave.recipe-definition.v1\0')
    .update(text, 'utf8')
    .digest('hex');
}

function rejects(operation: () => unknown, code: RecipeDefinitionErrorCode): void {
  expect(operation).toThrow(RecipeDefinitionError);
  expect(operation).toThrow(`Recipe definition rejected: ${code}`);
  try {
    operation();
  } catch (error: unknown) {
    expect(error).toHaveProperty('code', code);
    expect(error).not.toHaveProperty('cause');
  }
}

describe('external recipe definition', () => {
  it('pins exact canonical bytes and an independently calculated SHA-256 fixture', () => {
    const result = createRecipeDefinition(input);
    expect(result).toEqual({ ...input, canonicalJson, digest: fixtureDigest });
    expect(Buffer.from(result.canonicalJson)).toEqual(Buffer.from(canonicalJson));
    expect(decodeRecipeDefinition(Buffer.from(canonicalJson), fixtureDigest)).toEqual(result);
    expect(createHash('sha256').update(canonicalJson).digest('hex')).not.toBe(fixtureDigest);
  });

  it('snapshots strings, freezes the result, and owns no mutable byte array', () => {
    const source = { ...input };
    const result = createRecipeDefinition(source);
    source.configuration = 'changed';
    expect(Object.isFrozen(result)).toBe(true);
    expect(result.configuration).toBe('');
    const bytes = Buffer.from(canonicalJson);
    const decoded = decodeRecipeDefinition(bytes, fixtureDigest);
    bytes.fill(0);
    expect(decoded.canonicalJson).toBe(canonicalJson);
    expect(decoded.digest).toBe(fixtureDigest);
    expect(Object.isFrozen(decoded)).toBe(true);
  });

  it('accepts null-prototype data and ignores source property order', () => {
    const source: unknown = Object.assign(Object.create(null), {
      configuration: '',
      provider: input.provider,
      name: input.name,
    });
    expect(createRecipeDefinition(source).canonicalJson).toBe(canonicalJson);
  });

  it('keeps opaque text, control characters, JSON, and Unicode unchanged', () => {
    const configuration = '{"opaque":[{"x":1}]}\\/"\b\f\n\r\t\0\u001f\u00e9\u2028\ud83d\ude00';
    const result = createRecipeDefinition({ ...input, configuration });
    expect(result.canonicalJson).toBe(JSON.stringify({ ...input, configuration }));
    expect(result.canonicalJson).toContain('\\b\\f\\n\\r\\t\\u0000\\u001f');
    const decoded = decodeRecipeDefinition(Buffer.from(result.canonicalJson), result.digest);
    expect(decoded).toEqual(result);
    const composed = createRecipeDefinition({ ...input, configuration: '\u00e9' });
    const decomposed = createRecipeDefinition({ ...input, configuration: 'e\u0301' });
    expect(composed.digest).not.toBe(decomposed.digest);
  });

  it('content-addresses every field and does not resolve provider identifiers', () => {
    for (const change of [
      { name: 'other' },
      { provider: 'uninstalled_provider' },
      { provider: 'example.provider' },
      { configuration: 'other' },
    ]) {
      const result = createRecipeDefinition({ ...input, ...change });
      expect(result.digest).not.toBe(fixtureDigest);
      const decoded = decodeRecipeDefinition(Buffer.from(result.canonicalJson), result.digest);
      expect(decoded).toEqual(result);
    }
  });

  it.each([null, undefined, 1, true, '', [], Object('value')].map((value) => ({ value })))(
    'rejects non-record input %s',
    ({ value }) => rejects(() => createRecipeDefinition(value), 'invalid_object'),
  );

  it('rejects missing, extra, symbol, inherited, and non-enumerable fields', () => {
    for (const value of [
      {},
      { name: input.name, provider: input.provider },
      { ...input, extra: '' },
      { ...input, [Symbol('extra')]: '' },
      Object.create(input),
    ]) {
      expect(() => createRecipeDefinition(value)).toThrow(RecipeDefinitionError);
    }
    const hidden = { ...input };
    Object.defineProperty(hidden, 'name', { value: input.name, enumerable: false });
    rejects(() => createRecipeDefinition(hidden), 'invalid_fields');
  });

  it('rejects accessors and proxies without invoking caller code', () => {
    const getter = vi.fn(() => 'sensitive-content');
    const source = { ...input };
    Object.defineProperty(source, 'configuration', { get: getter });
    rejects(() => createRecipeDefinition(source), 'invalid_fields');
    expect(getter).not.toHaveBeenCalled();
    const trap = vi.fn(() => {
      throw new Error('sensitive-content');
    });
    rejects(
      () => createRecipeDefinition(new Proxy(input, { getPrototypeOf: trap, ownKeys: trap })),
      'invalid_object',
    );
    expect(trap).not.toHaveBeenCalled();
    const revoked = Proxy.revocable(input, {});
    revoked.revoke();
    rejects(() => createRecipeDefinition(revoked.proxy), 'invalid_object');
  });

  it.each(['', '-a', 'a-', 'a--b', 'A', 'a_b', 'a.b', 'a/b', 'a\n', '\u00e9', 'a'.repeat(65)])(
    'rejects noncanonical names %j',
    (name) => rejects(() => createRecipeDefinition({ ...input, name }), 'invalid_name'),
  );

  it.each([
    '',
    'Provider',
    '_a',
    'a_',
    'a__b',
    'a.-b',
    '../provider',
    'https://example.com',
    'file:provider',
    '@scope/provider',
    'a\\b',
    'a\n',
    'a'.repeat(129),
  ])('rejects noncanonical provider identifiers %j', (provider) => {
    rejects(() => createRecipeDefinition({ ...input, provider }), 'invalid_provider');
  });

  it.each([null, undefined, 0, false, [], {}, Object('text')].map((value) => ({ value })))(
    'rejects nonstring fields %s without traversing them',
    ({ value }) => {
      rejects(() => createRecipeDefinition({ ...input, name: value }), 'invalid_name');
      rejects(() => createRecipeDefinition({ ...input, provider: value }), 'invalid_provider');
      rejects(
        () => createRecipeDefinition({ ...input, configuration: value }),
        'invalid_configuration',
      );
    },
  );

  it('rejects cyclic and hostile nested configuration without traversing it', () => {
    const nested: { self?: unknown } = {};
    nested.self = nested;
    rejects(
      () => createRecipeDefinition({ ...input, configuration: nested }),
      'invalid_configuration',
    );
    const trap = vi.fn(() => {
      throw new Error('sensitive-content');
    });
    rejects(
      () => createRecipeDefinition({ ...input, configuration: new Proxy({}, { get: trap }) }),
      'invalid_configuration',
    );
    expect(trap).not.toHaveBeenCalled();
  });

  it.each(['\ud800', '\udfff', '\ud800x', '\ud800\ud800', '\udc00\ud800'])(
    'rejects unpaired surrogates %j',
    (configuration) => {
      rejects(() => createRecipeDefinition({ ...input, configuration }), 'invalid_configuration');
      const text = JSON.stringify({ ...input, configuration });
      const bytes = Buffer.from(text);
      rejects(() => decodeRecipeDefinition(bytes, digest(text)), 'invalid_configuration');
    },
  );

  it('accepts identifier maxima and the exact UTF-8 configuration bound', () => {
    for (const configuration of [
      'x'.repeat(recipeDefinitionLimits.configurationBytes),
      '\u00e9'.repeat(recipeDefinitionLimits.configurationBytes / 2),
      '\u0800'.repeat(recipeDefinitionLimits.configurationBytes / 3),
      '\ud83d\ude00'.repeat(recipeDefinitionLimits.configurationBytes / 4),
    ]) {
      const result = createRecipeDefinition({
        name: 'n'.repeat(64),
        provider: 'p'.repeat(128),
        configuration,
      });
      const decoded = decodeRecipeDefinition(Buffer.from(result.canonicalJson), result.digest);
      expect(decoded).toEqual(result);
      rejects(
        () => createRecipeDefinition({ ...input, configuration: `${configuration}x` }),
        'configuration_too_large',
      );
    }
  });

  it('enforces the exact encoded bound independently of the raw configuration bound', () => {
    const available = recipeDefinitionLimits.encodedBytes - Buffer.byteLength(canonicalJson);
    const configuration = '\0'.repeat(Math.floor(available / 6)) + 'x'.repeat(available % 6);
    const result = createRecipeDefinition({ ...input, configuration });
    expect(Buffer.byteLength(result.canonicalJson)).toBe(recipeDefinitionLimits.encodedBytes);
    const decoded = decodeRecipeDefinition(Buffer.from(result.canonicalJson), result.digest);
    expect(decoded).toEqual(result);
    rejects(
      () => createRecipeDefinition({ ...input, configuration: `${configuration}x` }),
      'definition_too_large',
    );
    const oversized = new Uint8Array(recipeDefinitionLimits.encodedBytes + 1);
    rejects(() => decodeRecipeDefinition(oversized, fixtureDigest), 'definition_too_large');
  });

  it.each([
    ` ${canonicalJson}`,
    `${canonicalJson}\n`,
    '{"provider":"local-provider","name":"sample","configuration":""}',
    '{"name":"sample","name":"sample","provider":"local-provider","configuration":""}',
    '{"name":"other","name":"sample","provider":"local-provider","configuration":""}',
    '{"name":"\\u0073ample","provider":"local-provider","configuration":""}',
    '{"name":"sample", "provider":"local-provider","configuration":""}',
  ])('rejects alternate raw representations even with a matching raw digest', (text) => {
    const bytes = Buffer.from(text);
    rejects(() => decodeRecipeDefinition(bytes, digest(text)), 'noncanonical_definition');
  });

  it('rejects alternate escapes and handles escaped quotes during shallow checking', () => {
    const result = createRecipeDefinition({ ...input, configuration: '/\\"{[]}' });
    const decoded = decodeRecipeDefinition(Buffer.from(result.canonicalJson), result.digest);
    expect(decoded).toEqual(result);
    const text = result.canonicalJson.replace('/', '\\/');
    const bytes = Buffer.from(text);
    rejects(() => decodeRecipeDefinition(bytes, digest(text)), 'noncanonical_definition');
  });

  it.each(['{', 'not-json', `${canonicalJson}garbage`, `\ufeff${canonicalJson}`])(
    'rejects malformed JSON and byte-order marks',
    (text) => {
      const bytes = Buffer.from(text);
      rejects(() => decodeRecipeDefinition(bytes, digest(text)), 'invalid_json');
    },
  );

  it('rejects nested containers before JSON parsing, including deep malformed input', () => {
    for (const text of [
      '{"name":"sample","provider":"local-provider","configuration":{',
      '{"name":"sample","provider":"local-provider","configuration":[',
      '['.repeat(32000),
      '{"configuration":' + '{'.repeat(32000),
    ]) {
      rejects(() => decodeRecipeDefinition(Buffer.from(text), digest(text)), 'invalid_fields');
    }
  });

  it.each([
    Uint8Array.of(0xff),
    Uint8Array.of(0xc0, 0xaf),
    Uint8Array.of(0xe2, 0x82),
    Uint8Array.of(0xed, 0xa0, 0x80),
    Uint8Array.of(0xf4, 0x90, 0x80, 0x80),
  ])('rejects malformed UTF-8 %j', (bytes) => {
    rejects(() => decodeRecipeDefinition(bytes, fixtureDigest), 'invalid_utf8');
  });

  it.each(
    [null, undefined, '', [], new ArrayBuffer(4), new Uint16Array(4), new Uint8Array(0)].map(
      (value) => ({ value }),
    ),
  )('rejects non-byte or empty input', ({ value }) => {
    rejects(() => decodeRecipeDefinition(value, fixtureDigest), 'invalid_bytes');
  });

  it.each([
    { text: 'null', code: 'invalid_object' },
    { text: '{}', code: 'invalid_fields' },
    { text: '{"name":"sample","provider":"local-provider"}', code: 'invalid_fields' },
    { text: canonicalJson.replace('""}', '"","extra":""}'), code: 'invalid_fields' },
    { text: canonicalJson.replace('"sample"', '1'), code: 'invalid_name' },
    { text: canonicalJson.replace('"local-provider"', 'false'), code: 'invalid_provider' },
    { text: canonicalJson.replace('""}', 'null}'), code: 'invalid_configuration' },
  ] satisfies readonly { text: string; code: RecipeDefinitionErrorCode }[])(
    'validates decoded root shape and every field',
    ({ text, code }) => rejects(() => decodeRecipeDefinition(Buffer.from(text), digest(text)), code),
  );

  it('rejects shared, detached, and proxied byte storage', () => {
    rejects(
      () => decodeRecipeDefinition(new Uint8Array(new SharedArrayBuffer(4)), fixtureDigest),
      'invalid_bytes',
    );
    const detached = new Uint8Array(4);
    structuredClone(detached.buffer, { transfer: [detached.buffer] });
    rejects(() => decodeRecipeDefinition(detached, fixtureDigest), 'invalid_bytes');
    rejects(
      () => decodeRecipeDefinition(new Proxy(Buffer.from(canonicalJson), {}), fixtureDigest),
      'invalid_bytes',
    );
  });

  it('copies only the supplied view and never invokes byte accessors or iterators', () => {
    const storage = Buffer.from(`x${canonicalJson}x`);
    const bytes = storage.subarray(1, storage.length - 1);
    const trap = vi.fn(() => {
      throw new Error('sensitive-content');
    });
    Object.defineProperty(bytes, 'byteLength', { get: trap });
    Object.defineProperty(bytes, 'buffer', { get: trap });
    Object.defineProperty(bytes, Symbol.iterator, { value: trap });
    expect(decodeRecipeDefinition(bytes, fixtureDigest).canonicalJson).toBe(canonicalJson);
    expect(trap).not.toHaveBeenCalled();
  });

  it.each([
    null,
    1,
    '',
    'a'.repeat(63),
    'a'.repeat(65),
    'g'.repeat(64),
    fixtureDigest.toUpperCase(),
  ])('rejects invalid expected digests', (expected) => {
    const bytes = Buffer.from(canonicalJson);
    rejects(() => decodeRecipeDefinition(bytes, expected), 'invalid_digest');
  });

  it('rejects a validly shaped wrong digest without echoing source data', () => {
    rejects(
      () => decodeRecipeDefinition(Buffer.from(canonicalJson), '0'.repeat(64)),
      'digest_mismatch',
    );
    const secret = 'sensitive-content';
    try {
      createRecipeDefinition({ ...input, name: secret, configuration: `${secret}\ud800` });
      expect.unreachable('invalid configuration was accepted');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(RecipeDefinitionError);
      expect(String(error)).not.toContain(secret);
    }
  });
});
