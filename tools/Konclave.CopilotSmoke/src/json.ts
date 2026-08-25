export type JsonRecord = Record<string, unknown>;

export function requireRecord(value: unknown, label: string): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  return value as JsonRecord;
}

export function requireString(
  record: JsonRecord,
  name: string,
  label: string,
): string {
  const value = record[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label}.${name} must be a non-empty string.`);
  }
  return value;
}

export function requireArray(
  record: JsonRecord,
  name: string,
  label: string,
): unknown[] {
  const value = record[name];
  if (!Array.isArray(value)) {
    throw new Error(`${label}.${name} must be an array.`);
  }
  return value;
}

export function optionalString(
  record: JsonRecord,
  name: string,
): string | undefined {
  const value = record[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
