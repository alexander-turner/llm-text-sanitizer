/**
 * Property/fuzz tests for the confusable-folding core. Example tests pin known
 * shapes; these pin the INVARIANTS over the real input domain so a future edit
 * surfaces a counterexample anywhere — not just at the hand-picked cases.
 *
 * The confusable scanner is INJECTED as a deterministic fake matching the
 * documented `{ findings: [{ index, char, latinEquivalent }] }` shape, so the
 * folder's offset/length/null logic is exercised independently of any engine.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { foldConfusables, normalizeConfusables } from "../src/confusables.mjs";
import { fcRunOptions, cp } from "./test-helpers.mjs";

const runOptions = fcRunOptions({ numRuns: 500 });
const check = (arbitrary, predicate) =>
  fc.assert(fc.property(arbitrary, predicate), runOptions);

// Confusable glyphs → ASCII canon. Mix of BMP (1 unit) and astral (2 units) so
// length-changing folds are exercised. ASCII chars in the alphabet are never
// flagged (they are the canon, not a confusable).
const FOLD_MAP = {
  [cp(0x0430)]: "a", // Cyrillic а
  [cp(0x043e)]: "o", // Cyrillic о
  [cp(0x0435)]: "e", // Cyrillic е
  [cp(0x0440)]: "p", // Cyrillic р
  [cp(0x0441)]: "c", // Cyrillic с
  [cp(0x1d400)]: "a", // 𝐀 mathematical bold A (astral)
  [cp(0x1d401)]: "b", // 𝐁 (astral)
};

/** Deterministic confusable scanner over FOLD_MAP, iterating by code point. */
const scan = (text) => {
  const findings = [];
  let index = 0;
  for (const ch of text) {
    if (Object.prototype.hasOwnProperty.call(FOLD_MAP, ch))
      findings.push({ index, char: ch, latinEquivalent: FOLD_MAP[ch] });
    index += ch.length;
  }
  return { findings };
};

/**
 * Reference fold computed independently of the implementation: walk the input
 * by code point and replace each flagged glyph. Order-independent, so it is a
 * fair oracle for the highest-index-first splice.
 */
const manualFold = (text) => {
  let out = "";
  for (const ch of text)
    out += Object.prototype.hasOwnProperty.call(FOLD_MAP, ch)
      ? FOLD_MAP[ch]
      : ch;
  return out;
};

// Alphabet: confusables (BMP + astral), plain ASCII anchors, a benign non-ASCII
// non-confusable (é, never flagged), and structural chars.
const charCp = fc.constantFrom(
  0x0430,
  0x043e,
  0x0435,
  0x0440,
  0x0441,
  0x1d400,
  0x1d401,
  0x61, // a
  0x2f, // /
  0x2e, // .
  0x20, // space
  0xe9, // é (non-ASCII, non-confusable)
);
const text = fc
  .array(charCp, { maxLength: 60 })
  .map((codes) => codes.map((c) => cp(c)).join(""));

// Any UTF-16 unit including lone surrogates, to prove the fold never throws on
// astral / malformed input even when scan returns findings for known glyphs.
const anyUnit = fc
  .array(fc.oneof(charCp, fc.constantFrom(0xd800, 0xdc00, 0xdbff, 0xdfff)), {
    maxLength: 60,
  })
  .map((codes) =>
    codes
      .map((code) => (code <= 0xffff ? String.fromCharCode(code) : cp(code)))
      .join(""),
  );

describe("foldConfusables (property)", () => {
  it("equals an independent manual fold (only flagged spans change)", () => {
    check(text, (t) => {
      assert.equal(foldConfusables(t, scan(t).findings), manualFold(t));
    });
  });

  it("leaves every non-flagged code point untouched", () => {
    check(text, (t) => {
      const folded = foldConfusables(t, scan(t).findings);
      // Strip all confusable glyphs from input and their ASCII canon from
      // output: the remaining code-point sequences must be identical.
      const flagged = new Set(Object.keys(FOLD_MAP));
      const canon = new Set(Object.values(FOLD_MAP));
      const inputRest = [...t].filter((ch) => !flagged.has(ch)).join("");
      const outputRest = [...folded].filter((ch) => !canon.has(ch)).join("");
      // inputRest may still contain "a" (ASCII anchor) which is also a canon
      // value, so compare only the non-canon residue of the input.
      const inputResidue = [...inputRest]
        .filter((ch) => !canon.has(ch))
        .join("");
      assert.equal(outputRest, inputResidue);
    });
  });

  it("keeps offsets correct when a fold changes length (astral 2→1)", () => {
    check(text, (t) => {
      // A length-changing fold that mis-splices would diverge from the manual
      // oracle; equality across fuzzed astral placements pins offset handling.
      assert.equal(foldConfusables(t, scan(t).findings), manualFold(t));
    });
  });

  it("never throws on astral / lone-surrogate input", () => {
    check(anyUnit, (t) => {
      assert.equal(typeof foldConfusables(t, scan(t).findings), "string");
    });
  });

  it("is idempotent: a second fold finds nothing to change", () => {
    check(text, (t) => {
      const once = foldConfusables(t, scan(t).findings);
      assert.equal(foldConfusables(once, scan(once).findings), once);
    });
  });
});

describe("normalizeConfusables (property)", () => {
  it("returns null exactly when no mapped field changed", () => {
    check(text, (t) => {
      const input = { file_path: t };
      const result = normalizeConfusables("Read", input, { scan });
      const folded = foldConfusables(t, scan(t).findings);
      // null iff the field is unchanged by folding.
      assert.equal(result === null, folded === t);
      if (result !== null) {
        assert.equal(result.updatedInput.file_path, folded);
        // The original input object is not mutated.
        assert.equal(input.file_path, t);
      }
    });
  });

  it("never touches all-ASCII commands (fast-path) — null", () => {
    const asciiText = fc
      .array(fc.integer({ min: 0x20, max: 0x7e }), { maxLength: 60 })
      .map((codes) => codes.map((c) => String.fromCharCode(c)).join(""));
    check(asciiText, (command) =>
      assert.equal(normalizeConfusables("Bash", { command }, { scan }), null),
    );
  });

  it("ignores tools with no mapped field", () => {
    check(text, (value) =>
      assert.equal(
        normalizeConfusables("Grep", { pattern: value }, { scan }),
        null,
      ),
    );
  });

  it("is idempotent: the folded form has nothing left to normalize", () => {
    check(text, (t) => {
      const first = normalizeConfusables("Read", { file_path: t }, { scan });
      if (first === null) return;
      assert.equal(
        normalizeConfusables("Read", first.updatedInput, { scan }),
        null,
      );
    });
  });

  it("never throws on astral / lone-surrogate field values", () => {
    check(anyUnit, (t) => {
      const result = normalizeConfusables("Read", { file_path: t }, { scan });
      assert.ok(
        result === null || typeof result.updatedInput.file_path === "string",
      );
    });
  });
});
