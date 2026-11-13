# Reader experience and local protocol explorer

The published `index.html` keeps the live Stitch implementation and all six model-derived operator journeys. A reader-facing surface introduces the object/recovery problem before advanced operations:

1. A resolution-independent SVG traces an object through three XOR fragments and reconstruction with one unavailable route.
2. A local interactive example uses the actual `createObject` and `recoverObject` implementations. It accepts up to 256 UTF-8 bytes, supports all fragment pairs, absent fragments and deliberate single-byte mutation, and exposes the complete object commitment.
3. A five-layer map separates commitments, scheduling, custody, pure computation and transport.
4. A generated facet inventory links to source, shows declaration counts and explicitly identifies inventory rather than proof evidence.
5. The existing live operator console retains every control ID, model-derived guard, network opt-in and evidence label.

The explorer never calls transport or writes live objects. Its sample and state exist only in page memory. It sends no input text, does not save data or keys, and does not renew or consume the live network resource ledger. The existing console's external diagnostics are separate from this local example.

## Evidence and failure semantics

A successful local reconstruction is a real cryptographic check of supplied bytes. It is not remote custody, independent peer identity, availability or durable retention evidence. Fewer than two fragments yields no accepted output. A changed supplied fragment is rejected even if two other supplied fragments are valid, matching the runtime's verify-every-input behavior. Withhold the altered fragment to test recovery from the two remaining intact fragments.

The object input ceiling is measured in UTF-8 bytes, not JavaScript character count. An invalid new input hides the previous result. Generation checks reject stale asynchronous completions. New encoding hides prior controls and results until the exact new input is committed. Empty objects remain valid; their zero-byte fragments cannot be meaningfully byte-mutated, so mutation controls are disabled.

The explorer runs real commitments for its bounded example. It does not prove browser cryptography. The facet catalog's counts are source inventory and its evidence labels are not a native acceptance certificate. Retained proof evidence applies only to the exact source and tool identities recorded by its producing verifier.

## Navigation and accessibility

Reader navigation uses native buttons and nonanimated scroll/focus changes. It never changes the URL fragment because Stitch already uses that fragment as the mesh key. All original operator navigation remains source-owned. The example uses native controls, visible labels, state descriptions in text, polite status updates, sufficient contrast and a reduced-motion fallback. No information is conveyed only by color. The SVG has a descriptive equivalent in text. Layouts adapt to phone screens; dense operator tables scroll within their panels.

## Checks

- `node --test tests/site-explorer.test.js`: every fragment pair, empty/odd/Unicode objects, mutation refusal, immutable original bytes, UTF-8 limits, safe source navigation, renderer schema validation, interrupted encodes and stale inspection results.
- `npx playwright test --config tests/browser/playwright.config.mjs site.spec.mjs`: shipped-page interaction, loss/tamper/reset, encoding updates, interruption handling, hash preservation, desktop/mobile overflow and screenshots.
- Existing operator and product suites continue to cover the live console.

Browser tests block non-local requests. Their results qualify the tested local scenario, not public-provider interoperability or physical peer networks.
