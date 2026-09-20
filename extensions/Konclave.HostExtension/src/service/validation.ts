export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function requireHexIdentifier(
  value: unknown,
  characters: number,
  label: string,
): string {
  if (
    typeof value !== 'string' ||
    value.length !== characters ||
    !/^[0-9a-f]+$/u.test(value)
  ) {
    throw new Error(`a ${characters}-character hex ${label} is required`);
  }
  return value;
}
