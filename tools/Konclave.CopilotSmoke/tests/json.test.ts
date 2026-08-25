import { describe, expect, it } from "vitest";

import {
  optionalString,
  requireArray,
  requireRecord,
  requireString,
} from "../src/json.js";

describe("JSON boundary helpers", () => {
  it("accepts required records, strings, and arrays", () => {
    const record = requireRecord({ id: "value", items: [] }, "result");
    expect(requireString(record, "id", "result")).toBe("value");
    expect(requireArray(record, "items", "result")).toEqual([]);
  });

  it("rejects invalid boundary values", () => {
    expect(() => requireRecord([], "result")).toThrow();
    expect(() => requireString({}, "id", "result")).toThrow();
    expect(() => requireArray({}, "items", "result")).toThrow();
  });

  it("returns only non-empty optional strings", () => {
    expect(optionalString({ id: "value" }, "id")).toBe("value");
    expect(optionalString({ id: "" }, "id")).toBeUndefined();
  });
});
