const ciMarkers = [
  "CI",
  "GITHUB_ACTIONS",
  "TF_BUILD",
  "BUILDKITE",
  "CIRCLECI",
  "GITLAB_CI",
  "JENKINS_URL",
] as const;

function isEnabled(value: string | undefined): boolean {
  if (!value) {
    return false;
  }
  return !["0", "false", "no", "off"].includes(value.trim().toLowerCase());
}

/** Refuses live Copilot inference whenever a recognized CI marker is active. */
export function assertLocalAgentSmoke(environment: NodeJS.ProcessEnv): void {
  const active = ciMarkers.filter((name) => isEnabled(environment[name]));
  if (active.length > 0) {
    throw new Error(
      `Live Copilot smoke is local-only; active CI markers: ${active.join(", ")}`,
    );
  }
}
