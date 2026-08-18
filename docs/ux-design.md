# UX and design resilience

Generated web interfaces should remain understandable and operable across input
methods, viewport sizes, content lengths, languages, and motion preferences.

## Semantics and keyboard access

Use native controls and landmarks before recreating them with generic elements. A
control has an accessible name, visible focus, keyboard behavior, and communicated
state.

Heading structure describes the page rather than visual font size. Labels,
instructions, validation messages, and loading/error/empty states remain available to
assistive technology.

WCAG 2.2 AA target size is 24 by 24 CSS pixels with documented exceptions and spacing
rules. Larger targets such as 44 by 44 can be a useful ergonomic goal, but are not the
AA minimum.

## Responsive and input behavior

Layout decisions follow available content/container space rather than named devices.
Use pointer/hover media features only when behavior depends on input capability.

Flex/grid children that contain long content often need `min-width: 0` or
`min-height: 0`. Long identifiers, URLs, translations, and project names need an
intentional wrapping policy such as `overflow-wrap: anywhere` at the narrow content
boundary.

Fixed edge UI accounts for safe-area insets. Images use appropriate responsive sources
and intrinsic dimensions.

## Localization and content stress

Prefer logical properties (`margin-inline`, `padding-block`, `inset-inline-start`) so
layout follows writing direction.

Use the project's `Intl`/i18n/pluralization primitives. Exercise long text, 30-40%
expansion, unbroken strings, CJK, emoji, and RTL before declaring a layout resilient.

Avoid fixed-height/width assumptions tied to short English copy.

## Motion and feedback

Motion communicates state, hierarchy, or spatial relationship. Honor
`prefers-reduced-motion: reduce` with an alternative that preserves meaning and
feedback instead of removing all state transitions blindly.

Loading, success, warning, error, disabled, empty, and offline states must remain
understandable without motion alone.

## Hierarchy and design systems

Use readable line length/line height, deliberate heading hierarchy, and spacing that
groups related controls/content.

Reuse existing tokens and components before adding one-off values. Preserve the
project's incumbent identity; this guidance does not impose one Genesis palette,
typeface, or component aesthetic.

## Primary references

- [WCAG 2.2 target size minimum](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html)
- [WCAG 2.2](https://www.w3.org/TR/WCAG22/)
- [MDN prefers-reduced-motion](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/At-rules/@media/prefers-reduced-motion)
- [MDN logical properties](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_logical_properties_and_values)
- [MDN pointer](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/At-rules/@media/pointer)
- [MDN hover](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/At-rules/@media/hover)
- [MDN overflow-wrap](https://developer.mozilla.org/en-US/docs/Web/CSS/overflow-wrap)
