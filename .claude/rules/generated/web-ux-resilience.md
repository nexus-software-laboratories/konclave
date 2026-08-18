---
# AUTO-GENERATED from .github/instructions/web-ux-resilience.instructions.md — do not edit
paths:
  - "**/*.astro"
  - "**/*.tsx"
  - "**/*.jsx"
  - "**/*.vue"
  - "**/*.svelte"
  - "**/*.css"
  - "**/*.scss"
---
# Web UX resilience

- Use semantic landmarks and native interactive controls. Every control has an
  accessible name, keyboard behavior, visible focus, and communicated state.
- Keep one descriptive H1 and sequential heading levels.
- Labels, instructions, validation, loading, empty, error, disabled, and offline
  states are programmatically and visually understandable.
- Meet WCAG 2.2 AA's 24-by-24 CSS-pixel target minimum or a documented exception/
  spacing case. Treat 44-by-44 as an ergonomic enhancement, not the AA rule.
- Change layouts from available container/content space, not named-device assumptions.
- Use `pointer`/`hover` media features only for input-capability differences.
- Prevent flex/grid overflow with the appropriate `min-width: 0`/`min-height: 0`;
  apply `overflow-wrap: anywhere` only at boundaries that must tolerate unbroken text.
- Use safe-area insets for fixed edge UI and responsive images with intrinsic sizes.
- Prefer logical CSS properties and the project's Intl/i18n/pluralization primitives.
- Check long text, 30-40% expansion, unbroken strings, CJK, emoji, and RTL.
- Honor `prefers-reduced-motion: reduce` while preserving meaningful state/feedback.
- Keep readable text measure, deliberate hierarchy, and spacing/grouping.
- Reuse existing tokens/components and project identity; do not impose a Genesis aesthetic.
- Before delivery, run the project review skill and report untested viewport,
  keyboard/focus, localization, and reduced-motion behavior.
