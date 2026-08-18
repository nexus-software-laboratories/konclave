# Security policy

Konclave is pre-release software. No released version is currently supported for
production use.

## Reporting a vulnerability

Report suspected vulnerabilities through GitHub's private vulnerability reporting
for this repository. Do not open a public issue or include exploit details, secrets,
private repository information, or internal infrastructure context in a discussion.

Include the affected revision, impact, reproduction conditions, and the smallest
safe proof needed to verify the report. Never include live credentials or private
message content.

## Public contribution boundary

Code from forks never runs on Konclave's self-hosted PitCrew capacity. Maintainers
review external contributions as source and reproduce accepted changes on a branch
in this repository before executing validation.

Public artifacts must not reference private repositories, hosted-service internals,
private operational topology, credentials, or nonpublic incident context.
