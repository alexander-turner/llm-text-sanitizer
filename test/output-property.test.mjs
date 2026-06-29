/**
 * Fast-check property tests for src/output.mjs. Pins the structural invariants
 * the example tests sample only at fixed points:
 *
 *   - sanitizeText never throws (no html/exfil, non-throwing redact) and its
 *     cleaned output carries no raw ESC byte and no payload-capable long
 *     invisible run after Layer 1;
 *   - `modified` is true exactly when cleaned !== input;
 *   - sanitizeValue preserves the JSON shape (key sets, array lengths) and is a
 *     no-op (deep-equal, modified=false) on all-clean input.
 *
 * Adversarial inputs are built from code points (never literal control bytes;
 * see CLAUDE.md > Code Style).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import {
  sanitizeText,
  sanitizeValue,
  deleteVerbatimSpans,
  MAX_DEPTH,
} from "../src/output.mjs";
import { fcRunOptions, cp } from "./test-helpers.mjs";

const runOptions = fcRunOptions({ numRuns: 300 });

const ESC = cp(0x1b);

// A lone surrogate is injected separately (fast-check v4 dropped fc.fullUnicode).
const loneSurrogate = fc
  .integer({ min: 0xd800, max: 0xdfff })
  .map((code) => String.fromCharCode(code));
const unicodeChar = fc
  .integer({ min: 0, max: 0x10ffff })
  .filter((code) => code < 0xd800 || code > 0xdfff)
  .map((code) => String.fromCodePoint(code));
// ESC + invisible/format chars + ANSI fragments + ordinary unicode/surrogates.
// Built from code points so no literal control byte sits in this source file.
const adversarialChar = fc.oneof(
  unicodeChar,
  loneSurrogate,
  fc.constantFrom(
    ESC, // bare ESC introducer
    `${ESC}[31m`, // SGR fragment
    `${ESC}[0m`,
    `${ESC}[32m`,
    cp(0x200b), // ZWSP (Cf)
    cp(0x200c), // ZWNJ (Cf, carve-out)
    cp(0x200d), // ZWJ (Cf, carve-out)
    cp(0xfe0f), // VS-16
    cp(0x00ad), // soft hyphen
    cp(0x2800), // braille blank filler
  ),
);
const adversarialInput = fc
  .array(adversarialChar, { maxLength: 200 })
  .map((parts) => parts.join(""));

const cpr = (a, b) => `${String.fromCodePoint(a)}-${String.fromCodePoint(b)}`;
// No payload-capable long invisible run may survive Layer 1. STRIP categories:
// Cf format, the variation selectors, and the blank-rendering fillers — built
// from code points so this source holds no literal invisible byte.
const LONG_INVISIBLE_RUN = new RegExp(
  `(?:\\p{Cf}|[${cpr(0xfe00, 0xfe0f)}]|[${cpr(0xe0100, 0xe01ef)}]|[\u115F\u1160\u3164\uFFA0\u2800]){10,}`,
  "u",
);

describe("property: sanitizeText invariants (Layer 1 only)", () => {
  it("never throws and produces ESC-free, payload-run-free cleaned text", async () => {
    await fc.assert(
      fc.asyncProperty(adversarialInput, async (input) => {
        const r = await sanitizeText(input);
        assert.equal(typeof r.cleaned, "string");
        assert.ok(!r.cleaned.includes(""), "raw ESC survived Layer 1");
        assert.doesNotMatch(
          r.cleaned,
          LONG_INVISIBLE_RUN,
          "a payload-capable invisible run survived Layer 1",
        );
        // `modified` faithfully tracks whether bytes changed.
        assert.equal(r.modified, r.cleaned !== input);
        // Any change carries at least one operator-visible warning (or the
        // SGR carve-out note) — content never vanishes silently.
        if (r.cleaned !== input)
          assert.ok(r.warnings.length > 0 || r.sgrNote === true);
      }),
      runOptions,
    );
  });

  it("is a no-op on text with no control/invisible chars", async () => {
    const benignChar = fc.constantFrom(..."0123456789 .,-_/:#%@".split(""));
    const benign = fc
      .array(benignChar, { minLength: 1, maxLength: 200 })
      .map((parts) => parts.join(""));
    await fc.assert(
      fc.asyncProperty(benign, async (input) => {
        const r = await sanitizeText(input);
        assert.equal(r.cleaned, input);
        assert.equal(r.modified, false);
        assert.deepEqual(r.warnings, []);
      }),
      runOptions,
    );
  });
});

// ─── sanitizeValue shape preservation ────────────────────────────────────────

const benignChar = fc.constantFrom(..."0123456789 .,-_/:#%@".split(""));
const benignString = fc
  .array(benignChar, { maxLength: 20 })
  .map((parts) => parts.join(""));
const nonStringScalar = fc.oneof(
  fc.integer(),
  fc.double({ noNaN: true }),
  fc.boolean(),
  fc.constant(null),
);
const objectOf = (valueArb) =>
  fc
    .dictionary(
      fc.string({ maxLength: 8 }).filter((key) => key !== "__proto__"),
      valueArb,
      { maxKeys: 5 },
    )
    .map((obj) => ({ ...obj }));

const { benignTree } = fc.letrec((tie) => ({
  benignTree: fc.oneof(
    { maxDepth: 4, withCrossShrink: true },
    benignString,
    nonStringScalar,
    fc.array(tie("benignTree"), { maxLength: 5 }),
    objectOf(tie("benignTree")),
  ),
}));
const { adversarialTree } = fc.letrec((tie) => ({
  adversarialTree: fc.oneof(
    { maxDepth: 4, withCrossShrink: true },
    adversarialInput,
    nonStringScalar,
    fc.array(tie("adversarialTree"), { maxLength: 5 }),
    objectOf(tie("adversarialTree")),
  ),
}));

// String leaves are wildcards (sanitizeText may rewrite them); every array
// length, object key set, and non-string scalar must match exactly.
function sameShape(before, after) {
  if (typeof before === "string") return typeof after === "string";
  if (Array.isArray(before))
    return (
      Array.isArray(after) &&
      before.length === after.length &&
      before.every((item, i) => sameShape(item, after[i]))
    );
  if (before !== null && typeof before === "object") {
    if (after === null || typeof after !== "object" || Array.isArray(after))
      return false;
    const keysBefore = Object.keys(before).sort();
    const keysAfter = Object.keys(after).sort();
    return (
      keysBefore.length === keysAfter.length &&
      keysBefore.every(
        (key, i) => key === keysAfter[i] && sameShape(before[key], after[key]),
      )
    );
  }
  return Object.is(before, after);
}

describe("property: sanitizeValue preserves structure", () => {
  it("returns a benign tree deep-equal and unchanged", async () => {
    await fc.assert(
      fc.asyncProperty(benignTree, async (value) => {
        const warnings = [];
        const r = await sanitizeValue(value, {}, warnings);
        assert.deepEqual(r.value, value);
        assert.equal(r.modified, false);
        assert.equal(warnings.length, 0);
      }),
      runOptions,
    );
  });

  it("preserves shape on adversarial leaves; modified iff a leaf changed", async () => {
    await fc.assert(
      fc.asyncProperty(adversarialTree, async (value) => {
        const warnings = [];
        const r = await sanitizeValue(value, {}, warnings);
        assert.ok(sameShape(value, r.value), "shape changed");
        let changed = false;
        try {
          assert.deepEqual(r.value, value);
        } catch {
          changed = true;
        }
        assert.equal(r.modified, changed);
      }),
      runOptions,
    );
  });

  // The depth fail-closed guard (R3) must never throw, regardless of how deep
  // the random nesting goes. Drive sanitizeValue with an array nested to a
  // random depth straddling MAX_DEPTH (some runs under, some well over) and
  // assert it resolves to a string leaf and never blows the stack.
  it("never throws on arbitrarily deep nesting (straddles MAX_DEPTH)", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: MAX_DEPTH * 3 }),
        async (depth) => {
          let node = "leaf";
          for (let i = 0; i < depth; i++) node = [node];
          const r = await sanitizeValue(node, {}, []);
          // Descend min(depth, MAX_DEPTH) array levels to the innermost value.
          let inner = r.value;
          const levels = Math.min(depth, MAX_DEPTH);
          for (let i = 0; i < levels; i++) {
            assert.ok(Array.isArray(inner));
            inner = inner[0];
          }
          assert.equal(typeof inner, "string");
          // Past the cap the innermost is the withhold placeholder; otherwise
          // the original (clean) leaf survives.
          assert.equal(
            inner,
            depth > MAX_DEPTH
              ? "[withheld: structured output nested beyond 200 levels]"
              : "leaf",
          );
        },
      ),
      runOptions,
    );
  });
});

// ─── deleteVerbatimSpans: deletion-only invariant ────────────────────────────

describe("property: deleteVerbatimSpans only deletes", () => {
  const safeText = fc
    .array(fc.constantFrom(..."abcXYZ ".split("")), { maxLength: 40 })
    .map((parts) => parts.join(""));
  const spanArb = fc.array(fc.constantFrom("X", "Y", "Z", "", "Q"), {
    maxLength: 4,
  });

  it("output length never grows and removed counts the cut spans", () => {
    fc.assert(
      fc.property(safeText, spanArb, (text, spans) => {
        const { text: out, removed } = deleteVerbatimSpans(text, spans);
        assert.ok(out.length <= text.length, "output grew");
        assert.ok(removed >= 0);
        // A non-zero removal must shorten the text; a zero removal leaves it.
        if (removed === 0) assert.equal(out, text);
        else assert.ok(out.length < text.length);
      }),
      runOptions,
    );
  });
});
