# llm-text-sanitizer

Sanitize untrusted text **before any model sees it**—in an agent, RAG, or
tool-use pipeline. It’s model- and provider-agnostic: it cleans bytes, not
prompts.

Three independent layers, each its own entry point so the heavy dependency
stays opt-in:

| Layer | Entry         | Does                                                         | Deps          |
| ----- | ------------- | ------------------------------------------------------------ | ------------- |
| 1     | `./invisible` | Strips payload-capable invisible Unicode and ANSI escapes    | none          |
| 2     | `./html`      | Splices out human-invisible HTML (comments, hidden elements) | remark/rehype |
| 3     | `./html`      | Detects data-exfil URLs (reports only, never rewrites)       | remark/rehype |

Layer 1 preserves ZWNJ/ZWJ where an orthography requires them (Arabic, Indic
scripts, emoji), so it won’t corrupt legitimate non-English text. Layer 2
preserves every byte outside a hidden range verbatim—no re-serialization, so
links, code, and tables are never reflowed. See
[THREAT-MODEL.md](./THREAT-MODEL.md) for the per-vector detail.

## Install

```sh
npm install llm-text-sanitizer
```

Node ≥ 20. ESM only.

## Usage

```js
import { sanitize } from "llm-text-sanitizer";

// Layer 1 only (invisible chars + ANSI) — no heavy deps:
const { cleaned, found, warnings } = await sanitize(untrustedText);

// Opt into the HTML layers (2 & 3) for web/HTML ingress:
const result = await sanitize(fetchedPageSource, { html: true });
//   result.cleaned   — hidden HTML spliced out, placeholders left behind
//   result.found     — categories neutralized, e.g. ["Format chars (Cf)", "hidden HTML"]
//   result.warnings  — human-facing notices (long-run alerts, exfil reasons, …)
```

`sanitize` never throws and never silently drops content: any change to the
text comes with at least one `warnings` entry.

Need just one layer? Import it directly:

```js
import { stripInvisible } from "llm-text-sanitizer/invisible"; // zero deps
import { sanitizeHtml, detectExfil } from "llm-text-sanitizer/html";
```

The `./html` entry pulls in the unified/remark/rehype graph (~200 ms of
module-load time); `sanitize` lazy-loads it only on the `{ html: true }` path,
so a Layer-1-only caller never pays for it. Every export is listed in the
[source](./src) JSDoc.

## Development

```sh
npm test         # node --test, 100% coverage enforced by c8
npm run lint     # eslint
npm run check    # tsc --noEmit (source is typed via JSDoc)
```

Coverage is enforced at 100% in CI; the enumerated members (each linguistic
script, invisible category, reported tag) are driven from single-source-of-truth
lists, so adding one without a test fails. Property/fuzz tests (fast-check)
exercise idempotence, deletion-only output, never-throwing on astral input, and
the `found` ⇔ changed invariant.

## Prior work

[`llm-sanitizer`](https://pypi.org/project/llm-sanitizer/) (Python) is the
closest: it scans untrusted documents over the same surfaces but _heuristically
flags_ suspicious patterns (“ignore previous instructions,” roleplay, base64)
and emits risk-scored reports. [llmsanitizer.com](https://llmsanitizer.com/) is
a hosted proxy for the outbound prompt (injection blocking, PII redaction,
jailbreaks). In npm, [`sanitize-html`](https://www.npmjs.com/package/sanitize-html)
misses CSS-hidden elements and reflows output, and the common invisible-char
strippers blanket-delete zero-width joiners, corrupting Indic scripts and emoji.

This library is deliberately narrower and deterministic: it doesn’t guess
intent, score risk, or redact PII—it neutralizes exactly the bytes a human
cannot see and reports the rest. Use it as the byte-level cleaning step _before_
a heuristic or model-based defense, not as a replacement for one.

## License

[Apache-2.0](./LICENSE)
