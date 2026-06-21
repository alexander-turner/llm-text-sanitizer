# Threat model

`llm-text-sanitizer` defends the boundary where untrusted text enters an
LLM-driven pipeline (agent tool output, RAG retrieval, fetched web pages). It is
a detect/neutralize layer, not an enforcement boundary: it makes hidden content
visible-or-gone and surfaces exfil-shaped URLs, so the model and the operator
see the same thing. Egress controls remain your enforcement layer.

The three layers are independent; use only the ones your ingress needs.

## Layer 1—invisible characters & ANSI (zero-dependency)

**What it removes**

| Category                   | Examples                                                       | Why it’s a payload channel                                    |
| -------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------- |
| Format chars (`Cf`)        | zero-width space/joiner, bidi overrides, Unicode **tag** chars | render blank but reach the model as bytes; tags smuggle ASCII |
| Variation selectors        | U+FE00–FE0F, U+E0100–E01EF                                     | not `Cf`; a run encodes a hidden payload                      |
| Blank-rendering fillers    | Hangul fillers U+115F/1160/3164/FFA0, Braille blank U+2800     | render blank, not `Cf`, so a naive `\p{Cf}` strip misses them |
| Soft hyphen / interior BOM | U+00AD, interior U+FEFF                                        | either can encode hidden instructions                         |
| ANSI / SGR escapes         | `ESC[…m`, cursor moves, OSC                                    | repaint or hide what an operator reads in a terminal          |

**What it preserves**

- A **single leading BOM** (a legitimate marker); interior BOMs are stripped.
- **ZWNJ (U+200C) / ZWJ (U+200D)** in genuine linguistic context: between two
  letters of a script whose orthography requires them (Arabic, Devanagari,
  Bengali, Gurmukhi, Gujarati, Oriya, Tamil, Telugu, Kannada, Malayalam,
  Sinhala) or inside an emoji ZWJ sequence. The carve-out fires only when **both**
  neighbors clearly belong to the context, and it is disabled once the total
  invisible count crosses a scatter floor—over-stripping beats under-stripping.

**Reassembly hardening.** Stripping an invisible char can reconstitute an ANSI
escape its split had hidden, and removing one ANSI sequence can reconstitute
another. Layer 1 strips ANSI to a fixed point and then sweeps any residual raw
control introducer—7-bit ESC (U+001B) or 8-bit C1 CSI (U+009B)—outright, so the
result carries no raw ANSI introducer for _any_ input and the operation is
idempotent.

## Layer 2—hidden HTML (remark/rehype)

For web/HTML ingress, splice out exactly what a human viewing the rendered page
cannot see:

- `<!-- HTML comments -->`
- elements hidden by inline style: `display:none`, `visibility:hidden`,
  `opacity:0`, off-screen positioning, zero/negative sizes, `text-indent`
  off-screen, collapsing `clip`/`clip-path`/`transform:scale(0)`, white-on-white
  / transparent text, `overflow:hidden` with a zero dimension
- elements hidden by attribute: `hidden`, `aria-hidden="true"`

Spliced ranges are replaced with a placeholder; **every byte outside a spliced
range is preserved verbatim** (no re-serialization). Unclosed hidden markup
extends to the end of the fragment—fail-closed for truncated input.

Scripting/resource tags (`script`, `style`, `object`, `embed`, `iframe`, `svg`,
`math`) and `data:` URI resources are **reported, not removed**: their bodies are
page source the model may legitimately need to inspect.

## Layer 3—exfil URLs (detection only)

Report—never rewrite—URLs in markdown links/images/definitions and HTML
attributes (`src`/`href`/`background`/`srcset`/`ping`, form `action`/`formaction`,
`meta refresh`) that are shaped to carry data off-origin:

- suspicious query/fragment parameters (long base64/hex blobs, credential-shaped
  tokens), tuned to skip request-signing / pagination / analytics parameters
  that are legitimately long (`X-Amz-*`, SAS, `cursor`, `utm_*`, `gclid`, …)
- oversized or active-content (`text/html`, `image/svg+xml`, JS) `data:` URIs
- embedded `user:password@host` credentials
- unusually long query strings or fragments
- encoded-data blobs smuggled in a path segment (a beacon that avoids the query)
- off-origin form actions and `meta refresh` redirects
- `javascript:` / `vbscript:` targets

Each threat carries a `reason` and the destination `host` (never the
payload-bearing query/fragment), suitable for a warning shown to the operator.
