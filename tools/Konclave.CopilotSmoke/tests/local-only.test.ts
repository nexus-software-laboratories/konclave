import { describe, expect, it } from "vitest";

import { assertLocalAgentSmoke } from "../src/local-only.js";

describe("assertLocalAgentSmoke", () => {
  it("allows an ordinary local environment", () => {
    expect(() => assertLocalAgentSmoke({})).not.toThrow();
  });

  it.each([
    "CI",
    "GITHUB_ACTIONS",
    "TF_BUILD",
    "BUILDKITE",
    "CIRCLECI",
    "GITLAB_CI",
    "JENKINS_URL",
  ])("rejects %s", (name) => {
    expect(() => assertLocalAgentSmoke({ [name]: "true" })).toThrow(
      /local-only/,
    );
  });

  it("treats explicit false values as inactive", () => {
    expect(() =>
      assertLocalAgentSmoke({ CI: "false", GITHUB_ACTIONS: "0" }),
    ).not.toThrow();
  });
});
