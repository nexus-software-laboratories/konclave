---
applyTo: "crates/**/*.rs,apps/**/*.{rs,ts,tsx},extensions/**/*.{ts,tsx},packages/**/*.{ts,tsx},tools/**/*.{rs,ts,tsx},scripts/**/*.ps1,proto/**/*.proto,policy/**/*.schema.json,docs/**/*.md"
scope: "Identifier and capability privacy contracts"
---

# Identifier privacy maintenance

- When adding an identifier or changing derivation, visibility, lifetime,
  authorization use, retry scope or logging, update
  `docs/reference/identifier-privacy.md` in the same change. Include shape,
  possession-alone authority, observers, correlation/abuse risk, exposure response
  and the current owning source; group equivalent values, not secret exceptions.
- Non-secret is not permission to publish live metadata. Never infer confidentiality
  or authority from a name, width, encoding or hash; separate IDs from bearer
  capabilities, private keys and secret-bearing nonces.
- For logging identifiers, privacy allowlisting takes precedence over generic
  safe-by-construction guidance: bounded size alone does not make an ID exportable.
- Verify classifications against the changed code and canonical contract. Update the
  threat model when a guarantee changes, preserve exact-retry identities, and mark
  deployment-dependent visibility explicitly. Review this alongside the boundary;
  link checks and green builds do not prove semantic classification is complete.
