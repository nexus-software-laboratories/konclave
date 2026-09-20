import { createHash } from 'node:crypto';
import { TextDecoder, types } from 'node:util';

/** Hard availability bounds, independent of provider semantics or local authority. */
export const recipeDefinitionLimits = Object.freeze({
  nameCharacters: 64,
  providerCharacters: 128,
  configurationBytes: 48 * 1024,
  encodedBytes: 64 * 1024,
});

/** Finite validation outcomes; errors never include definition or configuration content. */
export type RecipeDefinitionErrorCode =
  | 'invalid_object'
  | 'invalid_fields'
  | 'invalid_name'
  | 'invalid_provider'
  | 'invalid_configuration'
  | 'configuration_too_large'
  | 'definition_too_large'
  | 'invalid_bytes'
  | 'invalid_utf8'
  | 'invalid_json'
  | 'noncanonical_definition'
  | 'invalid_digest'
  | 'digest_mismatch';

/** A sanitized boundary rejection. Callers branch on code, not diagnostic text. */
export class RecipeDefinitionError extends Error {
  /** @param code The finite failed invariant; no source text is accepted. */
  constructor(readonly code: RecipeDefinitionErrorCode) {
    super(`Recipe definition rejected: ${code}`);
    this.name = 'RecipeDefinitionError';
  }
}

/**
 * Frozen, content-addressed data, not a provider installation, policy, or grant.
 * Configuration is opaque Unicode scalar text and is never interpreted by this codec.
 * canonicalJson contains exactly name, provider, configuration in that order.
 * digest is lowercase hexadecimal SHA-256 over UTF-8("konclave.recipe-definition.v1\0")
 * followed by UTF-8(canonicalJson). Neither field exposes shared mutable bytes.
 */
export interface RecipeDefinition {
  readonly name: string;
  readonly provider: string;
  readonly configuration: string;
  readonly canonicalJson: string;
  readonly digest: string;
}

const digestDomain = 'konclave.recipe-definition.v1\0';
const namePattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const providerPattern = /^[a-z0-9]+(?:[-_.][a-z0-9]+)*$/u;
const typedArrayPrototype: object = Object.getPrototypeOf(Uint8Array.prototype);
const byteLengthGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength')?.get;
const bufferGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer')?.get;

/**
 * Creates an immutable definition from exactly three own enumerable string data properties.
 * Only ordinary or null-prototype records are accepted; proxies and accessors are rejected.
 * Names use lowercase ASCII alphanumeric segments separated by hyphens. Provider identifiers
 * also allow underscores or dots between segments, but have no path, URL, or loading semantics.
 * No spelling or Unicode normalization is performed, and empty configuration is valid.
 * @param input Untrusted structured data, never an executable provider object.
 * @returns A frozen snapshot with canonical JSON and its domain-separated digest.
 * @throws {RecipeDefinitionError} For invalid shape, text, identifiers, or hard bounds.
 */
export function createRecipeDefinition(input: unknown): RecipeDefinition {
  if (typeof input !== 'object' || input === null || types.isProxy(input)) {
    throw new RecipeDefinitionError('invalid_object');
  }
  const prototype: unknown = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new RecipeDefinitionError('invalid_object');
  }
  const keys = Reflect.ownKeys(input);
  if (
    keys.length !== 3 ||
    !keys.includes('name') ||
    !keys.includes('provider') ||
    !keys.includes('configuration')
  ) {
    throw new RecipeDefinitionError('invalid_fields');
  }

  const name = stringProperty(input, 'name', 'invalid_name');
  const provider = stringProperty(input, 'provider', 'invalid_provider');
  const configuration = stringProperty(input, 'configuration', 'invalid_configuration');
  if (name.length > recipeDefinitionLimits.nameCharacters || namePattern.exec(name)?.[0] !== name) {
    throw new RecipeDefinitionError('invalid_name');
  }
  if (
    provider.length > recipeDefinitionLimits.providerCharacters ||
    providerPattern.exec(provider)?.[0] !== provider
  ) {
    throw new RecipeDefinitionError('invalid_provider');
  }

  const configurationJsonBytes = measureConfiguration(configuration);
  const emptyJson = JSON.stringify({ name, provider, configuration: '' });
  if (
    Buffer.byteLength(emptyJson, 'utf8') + configurationJsonBytes - 2 >
    recipeDefinitionLimits.encodedBytes
  ) {
    throw new RecipeDefinitionError('definition_too_large');
  }
  const canonicalJson = JSON.stringify({ name, provider, configuration });
  const digest = createHash('sha256')
    .update(digestDomain)
    .update(canonicalJson, 'utf8')
    .digest('hex');
  return Object.freeze({ name, provider, configuration, canonicalJson, digest });
}

/**
 * Decodes only the exact canonical bytes selected by an expected lowercase hexadecimal digest.
 * A bounded private snapshot is taken before content validation. Shared memory is rejected.
 * UTF-8 is fatal, JSON containers must be flat, and byte-for-byte re-encoding rejects duplicate
 * fields, alternate escaping, ordering, whitespace, and a leading byte-order mark.
 * @param input Untrusted Uint8Array (including Buffer); other values are rejected.
 * @param expectedDigest The independently selected 64-character lowercase SHA-256 digest.
 * @returns A frozen definition without retaining the caller's byte storage.
 * @throws {RecipeDefinitionError} For invalid bytes, encoding, shape, bounds, or digest.
 */
export function decodeRecipeDefinition(input: unknown, expectedDigest: unknown): RecipeDefinition {
  const bytes = copyBoundedBytes(input);
  if (
    typeof expectedDigest !== 'string' ||
    expectedDigest.length !== 64 ||
    !/^[0-9a-f]{64}$/u.test(expectedDigest)
  ) {
    throw new RecipeDefinitionError('invalid_digest');
  }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new RecipeDefinitionError('invalid_utf8');
  }
  rejectNestedContainers(text);
  let inputValue: unknown;
  try {
    inputValue = JSON.parse(text);
  } catch {
    throw new RecipeDefinitionError('invalid_json');
  }
  const definition = createRecipeDefinition(inputValue);
  if (!Buffer.from(definition.canonicalJson, 'utf8').equals(bytes)) {
    throw new RecipeDefinitionError('noncanonical_definition');
  }
  if (definition.digest !== expectedDigest) {
    throw new RecipeDefinitionError('digest_mismatch');
  }
  return definition;
}

function stringProperty(input: object, key: string, code: RecipeDefinitionErrorCode): string {
  const descriptor = Object.getOwnPropertyDescriptor(input, key);
  if (descriptor === undefined || !descriptor.enumerable || !('value' in descriptor)) {
    throw new RecipeDefinitionError('invalid_fields');
  }
  const value: unknown = descriptor.value;
  if (typeof value !== 'string') {
    throw new RecipeDefinitionError(code);
  }
  return value;
}

function measureConfiguration(value: string): number {
  if (value.length > recipeDefinitionLimits.configurationBytes) {
    throw new RecipeDefinitionError('configuration_too_large');
  }
  let utf8Bytes = 0;
  let escapingBytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new RecipeDefinitionError('invalid_configuration');
      }
      utf8Bytes += 4;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new RecipeDefinitionError('invalid_configuration');
    } else {
      utf8Bytes += unit <= 0x7f ? 1 : unit <= 0x7ff ? 2 : 3;
      if (unit === 0x22 || unit === 0x5c) {
        escapingBytes += 1;
      } else if (unit < 0x20) {
        escapingBytes += [8, 9, 10, 12, 13].includes(unit) ? 1 : 5;
      }
    }
  }
  if (utf8Bytes > recipeDefinitionLimits.configurationBytes) {
    throw new RecipeDefinitionError('configuration_too_large');
  }
  return utf8Bytes + escapingBytes + 2;
}

function copyBoundedBytes(input: unknown): Uint8Array {
  if (types.isProxy(input) || !types.isUint8Array(input)) {
    throw new RecipeDefinitionError('invalid_bytes');
  }
  // Intrinsic access bypasses caller-owned accessors and typed-array iterators.
  const length: unknown = byteLengthGetter?.call(input);
  const buffer: unknown = bufferGetter?.call(input);
  if (typeof length !== 'number' || length === 0 || types.isSharedArrayBuffer(buffer)) {
    throw new RecipeDefinitionError('invalid_bytes');
  }
  if (length > recipeDefinitionLimits.encodedBytes) {
    throw new RecipeDefinitionError('definition_too_large');
  }
  const bytes = new Uint8Array(length);
  try {
    bytes.set(input);
  } catch {
    throw new RecipeDefinitionError('invalid_bytes');
  }
  return bytes;
}

function rejectNestedContainers(text: string): void {
  let quoted = false;
  let escaped = false;
  let depth = 0;
  for (const character of text) {
    if (quoted) {
      if (escaped) {
        escaped = false;
      } else if (character === '\\') {
        escaped = true;
      } else if (character === '"') {
        quoted = false;
      }
    } else if (character === '"') {
      quoted = true;
    } else if (character === '[' || character === ']') {
      throw new RecipeDefinitionError('invalid_fields');
    } else if (character === '{') {
      depth += 1;
      if (depth > 1) {
        throw new RecipeDefinitionError('invalid_fields');
      }
    } else if (character === '}') {
      depth -= 1;
    }
  }
}
