/**
 * Semantic-correctness fuzzing for the hidden-HTML splice layer.
 *
 * html-property.test.mjs fuzzes STRUCTURAL invariants (idempotence, never
 * throws, placeholder bookkeeping) over arbitrary generated markup. Those
 * hold even if the splicer removes the WRONG element — it could satisfy
 * "output contains a placeholder" by splicing a visible <div> while leaving a
 * display:none payload intact, or by extending a hidden range over following
 * visible prose.
 *
 * This suite fuzzes PRECISION directly: build random documents interleaving
 * KNOWN-VISIBLE constructs (a rendered page shows them — they must survive
 * byte-for-byte, including near-miss styles like `display:inline`,
 * `opacity:1`, or ordinary absolute positioning) with KNOWN-HIDDEN constructs
 * (a rendered page never shows them — their payload marker must be gone), and
 * assert each specific piece's exact fate, not an aggregate invariant.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { sanitizeHtml } from "../src/html.mjs";
import { fcRunOptions } from "./test-helpers.mjs";

// Each KEEP token is a complete, visible construct that must survive verbatim.
// The styles are deliberate near-misses of the hidden heuristics: inline vs
// none, opacity 1 vs 0, visible vs hidden, on-screen absolute positioning,
// contrasting (not same-color) text, a decorative clip-path, an in-plane
// rotation, and a benign calc() offset the detector must fail OPEN on.
const KEEP_TOKENS = [
  "<p>plain visible paragraph KEEPPLAIN</p>",
  '<div style="color: red">KEEPRED</div>',
  '<span style="display: inline">KEEPINLINE</span>',
  '<div style="opacity: 1">KEEPOPAQUE</div>',
  '<div style="visibility: visible">KEEPVISIBLE</div>',
  '<div style="position: absolute; left: 10px; top: 20px">KEEPONSCREEN</div>',
  '<div style="position: absolute; left: calc(100% - 5px)">KEEPCALC</div>',
  '<div style="color: #fff; background: #000">KEEPCONTRAST</div>',
  '<div style="color: var(--fg); background: var(--fg)">KEEPVARCOLOR</div>',
  '<div style="transform: rotate(90deg)">KEEPROTATE</div>',
  '<div style="clip-path: circle(50%)">KEEPCLIP</div>',
  '<div style="font-size: 12px; height: 40px">KEEPSIZED</div>',
  '<div style="text-indent: 2em">KEEPINDENT</div>',
  '<div style="overflow: hidden; height: 100px">KEEPOVERFLOW</div>',
];

// Each STRIP token is a genuinely hidden construct; its MARKER (the payload a
// model would read but a human never sees) must be absent from the output.
const STRIP_TOKENS = [
  { t: '<div style="display:none">STRIPNONE</div>', marker: "STRIPNONE" },
  {
    t: '<div style="visibility: hidden">STRIPVISHID</div>',
    marker: "STRIPVISHID",
  },
  { t: "<div hidden>STRIPATTR</div>", marker: "STRIPATTR" },
  { t: "<!-- STRIPCOMMENT -->", marker: "STRIPCOMMENT" },
  {
    t: '<div style="position:absolute; left:-9999px">STRIPOFFSCREEN</div>',
    marker: "STRIPOFFSCREEN",
  },
  { t: '<span style="opacity: 0">STRIPOPACITY</span>', marker: "STRIPOPACITY" },
  {
    t: '<div style="color:#fff; background-color:#fff">STRIPWHITE</div>',
    marker: "STRIPWHITE",
  },
  {
    t: '<div style="font-size: 0">STRIPFONTZERO</div>',
    marker: "STRIPFONTZERO",
  },
  {
    t: '<p aria-hidden="true">STRIPARIA</p>',
    marker: "STRIPARIA",
  },
];

const pieceGen = fc.oneof(
  fc.constantFrom(...KEEP_TOKENS).map((t) => ({ kind: "keep", t })),
  fc
    .constantFrom(...STRIP_TOKENS)
    .map(({ t, marker }) => ({ kind: "strip", t, marker })),
  fc
    .array(fc.constantFrom(..."abc 0123456789 .,-_".split("")), {
      minLength: 1,
      maxLength: 12,
    })
    .map((cs) => ({ kind: "filler", t: cs.join("").trim() || "x" })),
);

// Blocks are joined with blank lines so each construct is its own markdown
// block; documents dense enough in tags also exercise the HTML-source branch
// (looksLikeHtmlSource), so both scanners get precision coverage.
const docGen = fc.array(pieceGen, { minLength: 1, maxLength: 10 });

describe("semantic-correctness fuzz: hidden-splice precision on mixed documents", () => {
  it("every visible construct survives byte-for-byte; every hidden payload is gone", () => {
    fc.assert(
      fc.property(docGen, (pieces) => {
        const text = pieces.map((p) => p.t).join("\n\n");
        const cleaned = sanitizeHtml(text)?.text ?? text;
        for (const p of pieces) {
          if (p.kind === "keep") {
            assert.ok(
              cleaned.includes(p.t),
              `visible construct mangled: ${p.t}\n--- input ---\n${text}\n--- output ---\n${cleaned}`,
            );
          } else if (p.kind === "strip") {
            assert.ok(
              !cleaned.includes(p.marker),
              `hidden payload survived: ${p.marker}\n--- input ---\n${text}\n--- output ---\n${cleaned}`,
            );
          }
        }
      }),
      fcRunOptions({ numRuns: 500 }),
    );
  });
});
