---
applyTo: "**/package.json,**/package-lock.json,.npmrc,.github/workflows/**/*.yml"
scope: "Node package manifests, npm configuration, and CI"
---

# Node package management

- A lockfile-free scaffold uses `npm install`; commit the generated
  `package-lock.json`, after which CI uses `npm ci`.
- Keep `package.json` and `package-lock.json` synchronized. Do not delete the lockfile
  to bypass dependency errors.
- Cache npm's download store only. Never cache `node_modules`.
- Follow [Node dependency installation](../../../../docs/development/node-dependencies.md)
  for the generated-project rationale.
