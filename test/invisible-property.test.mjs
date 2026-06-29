/**
 * Property (fuzz) tests for the ZWNJ/ZWJ carve-out over its real input domain:
 * random interleavings of joiner-using script letters, emoji parts, and the
 * joiners themselves. Pins the structural invariants the document-wide budget
 * must hold against any adversarial arrangement — not just the hand-built PoC.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import {
  stripInvisible,
  stripInvisibleWithReport,
  TOTAL_PRESERVED_JOINER_BUDGET,
} from "../src/invisible.mjs";
import { fcRunOptions, cp } from "./test-helpers.mjs";

const ZWNJ = cp(0x200c);
const ZWJ = cp(0x200d);

const countOf = (s, ch) => s.split(ch).length - 1;
const preservedJoiners = (s) => countOf(s, ZWNJ) + countOf(s, ZWJ);

// The carve-out's real domain: letters of joiner-using scripts (Arabic + a
// Devanagari pair), emoji bases + a skin-tone modifier, the two joiners, and a
// few plain visible chars to form gaps. No ASCII-only noise — feed the domain
// the change actually touches.
const carveChar = fc.constantFrom(
  cp(0x645), // Arabic
  cp(0x62e), // Arabic
  cp(0x915), // Devanagari
  cp(0x937), // Devanagari
  cp(0x1f468), // man (pictograph)
  cp(0x1f469), // woman (pictograph)
  cp(0x1f3fb), // skin-tone modifier
  ZWNJ,
  ZWJ,
  "a",
  " ",
);
const carveText = fc
  .array(carveChar, { maxLength: 120 })
  .map((parts) => parts.join(""));

describe("property: carve-out joiner-budget invariants", () => {
  it("output is always a subsequence of the input (deletion only)", () => {
    fc.assert(
      fc.property(carveText, (text) => {
        // Per code UNIT (astral chars are two units; the carve-out only ever
        // deletes whole code points, so a per-unit subsequence check is sound
        // and stricter than per-code-point here — no lone surrogates injected).
        const out = stripInvisible(text);
        let i = 0;
        for (let k = 0; k < out.length; k++) {
          const unit = out.charCodeAt(k);
          while (i < text.length && text.charCodeAt(i) !== unit) i++;
          assert.ok(i < text.length, "output not a subsequence of input");
          i++;
        }
      }),
      fcRunOptions(),
    );
  });

  it("is idempotent: strip(strip(x)) === strip(x)", () => {
    fc.assert(
      fc.property(carveText, (text) => {
        const once = stripInvisible(text);
        assert.equal(stripInvisible(once), once);
      }),
      fcRunOptions(),
    );
  });

  it("preserved-joiner count never exceeds the budget", () => {
    fc.assert(
      fc.property(carveText, (text) => {
        const { cleaned } = stripInvisibleWithReport(text);
        assert.ok(
          preservedJoiners(cleaned) <= TOTAL_PRESERVED_JOINER_BUDGET,
          `preserved ${preservedJoiners(cleaned)} > budget`,
        );
      }),
      fcRunOptions(),
    );
  });

  it("`found` is non-empty iff the text actually changed", () => {
    fc.assert(
      fc.property(carveText, (text) => {
        const { cleaned, found } = stripInvisibleWithReport(text);
        assert.equal(found.length > 0, cleaned !== text);
      }),
      fcRunOptions(),
    );
  });
});
