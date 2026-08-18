# Node dependency installation

Generated Node projects intentionally support two dependency states:

- A new scaffold has no committed `package-lock.json` because symbols, optional
  components, and composed frontends can change the final dependency graph.
- The first `npm install` creates a lockfile for the resolved project. Commit that
  lockfile so subsequent CI runs use `npm ci`.

The generated workflow checks for a lockfile on every run. Without one, it performs a
normal install and uses the shared npm download cache. With one, it performs the
reproducible clean install while retaining the same cache.

Keep `package.json` and `package-lock.json` together when dependencies change. Do not
delete the lockfile to bypass an install failure; refresh it deliberately with the
project's declared Node/npm toolchain and review the dependency delta.

`.npmrc` disables audit and funding network calls in routine installs while preserving
normal lockfile generation. Projects may change that policy explicitly after scaffold.
