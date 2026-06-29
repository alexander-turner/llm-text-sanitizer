/**
 * Unit + property tests for the zero-dependency invisible-char core.
 * Driven from the SSOT lists (CHECKS, BLANK_NON_CF, VS, LINGUISTIC_SCRIPTS) so
 * a dropped/added enumerated member surfaces as a failing or non-compiling
 * test, not merely a coverage gap.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import {
  stripInvisible,
  stripInvisibleWithReport,
  isSgrOnly,
  STRIP,
  SGR_RE,
  CHECKS,
  CATEGORY,
  CATEGORY_LABELS,
  VS,
  BLANK_NON_CF,
  ZERO_WIDTH_MN,
  LONG_RUN_RE,
  LONG_RUN_THRESHOLD,
  SCATTERED_THRESHOLD,
  CONSECUTIVE_JOINER_CAP,
  TOTAL_PRESERVED_JOINER_BUDGET,
  LINGUISTIC_SCRIPTS,
} from "../src/invisible.mjs";
import { applyLayer1 } from "../src/layer1.mjs";
import { fcRunOptions, cp } from "./test-helpers.mjs";

const ZWNJ = cp(0x200c);
const ZWJ = cp(0x200d);

/** Count occurrences of a single-char needle in a string (joiner counting). */
const countOf = (s, ch) => s.split(ch).length - 1;

// ─── stripInvisible: core classes ────────────────────────────────────────────

describe("stripInvisible: core classes", () => {
  for (const [name, input, expected] of [
    [
      "preserves single leading BOM, strips interior BOM + soft hyphen",
      `${cp(0xfeff)}a${cp(0xfeff)}b${cp(0x00ad)}c`,
      `${cp(0xfeff)}abc`,
    ],
    [
      "strips a leading soft hyphen entirely (no BOM branch)",
      `${cp(0x00ad)}abc`,
      "abc",
    ],
    [
      "strips a run of soft hyphens",
      `mal${cp(0x00ad).repeat(3)}ware`,
      "malware",
    ],
    ["returns empty string unchanged", "", ""],
    // Guards the VS set against a build that folds to a string of literal ASCII
    // (e.g. "undefined"): that would turn the char class into {u,n,d,e,f,i} and
    // start eating ordinary prose.
    [
      "leaves benign ASCII prose untouched",
      "defined unfixed key",
      "defined unfixed key",
    ],
  ]) {
    it(name, () => assert.equal(stripInvisible(input), expected));
  }

  // BLANK_NON_CF: one entry per member so dropping any member surfaces as a
  // failing test (100% line coverage fires the whole char class on a single
  // match — a dropped member is invisible to coverage alone).
  for (const ch of BLANK_NON_CF) {
    const hex = ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
    it(`strips blank-rendering filler U+${hex} (non-Cf)`, () => {
      const { cleaned, found } = stripInvisibleWithReport(`a${ch}b`);
      assert.equal(cleaned, "ab");
      assert.deepEqual(found, [CATEGORY.BLANK_FILLERS]);
    });
  }

  // Variation selectors are not category Cf, so the dedicated VS set — not
  // \p{Cf} — must catch them. Pin each sub-range's first, a mid entry, and last
  // so a truncated or off-by-one range survives in the output.
  for (const codePoint of [0xfe00, 0xfe0f, 0xe0100, 0xe0101, 0xe01ef]) {
    const hex = codePoint.toString(16).toUpperCase();
    it(`strips variation selector U+${hex}`, () => {
      const { cleaned, found } = stripInvisibleWithReport(`a${cp(codePoint)}b`);
      assert.equal(cleaned, "ab");
      assert.deepEqual(found, [CATEGORY.VARIATION_SELECTORS]);
    });
  }

  it("preserves a single leading BOM with nothing else to strip", () => {
    const input = `${cp(0xfeff)}clean leading bom`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });

  // One case per CHECKS category: the code reported must name exactly that
  // category, and every code must carry a human label. Drives from the SSOT so
  // a renamed/dropped category fails here.
  const categorySample = {
    [CATEGORY.CF]: cp(0x200b), // ZWSP
    [CATEGORY.VARIATION_SELECTORS]: cp(0xfe0f),
    [CATEGORY.BLANK_FILLERS]: cp(0x3164),
  };
  for (const [code] of CHECKS) {
    it(`reports the "${code}" category by its code`, () => {
      const sample = categorySample[code];
      assert.ok(sample, `no sample wired for CHECKS category "${code}"`);
      assert.ok(CATEGORY_LABELS[code], `no human label for category "${code}"`);
      const { cleaned, found } = stripInvisibleWithReport(`x${sample}y`);
      assert.equal(cleaned, "xy");
      assert.deepEqual(found, [code]);
    });
  }
});

// CATEGORY_LABELS is exported as the complete code→label map consumers use to
// render `found`. Library code only ever reads four of its entries, so without
// this guard a dropped or empty label for the other categories would ship
// silently. Drive off the CATEGORY SSOT and assert the key sets match exactly.
describe("CATEGORY_LABELS completeness", () => {
  const codes = Object.values(CATEGORY);
  for (const code of codes) {
    it(`maps "${code}" to a non-empty human label`, () => {
      assert.equal(typeof CATEGORY_LABELS[code], "string");
      assert.ok(CATEGORY_LABELS[code].length > 0);
    });
  }
  it("has no label without a matching CATEGORY code", () => {
    assert.deepEqual(Object.keys(CATEGORY_LABELS).sort(), [...codes].sort());
  });
});

// ─── ZWNJ/ZWJ linguistic carve-out ───────────────────────────────────────────
// "می‌خ" — ZWNJ between Arabic letters (Persian).
const PERSIAN = cp(0x645) + cp(0x6cc) + ZWNJ + cp(0x62e);
// "क्‍ष" — ZWJ between Devanagari virama and consonant.
const DEVANAGARI = cp(0x915) + cp(0x94d) + ZWJ + cp(0x937);
// 👨‍👩‍👧‍👦 — a four-person family emoji ZWJ sequence (no variation selectors).
const FAMILY =
  cp(0x1f468) + ZWJ + cp(0x1f469) + ZWJ + cp(0x1f467) + ZWJ + cp(0x1f466);

// Two representative letters per script for the carve-out preserve test.
const SCRIPT_LETTERS = {
  Arabic: [0x645, 0x62e],
  Devanagari: [0x915, 0x937],
  Bengali: [0x995, 0x99a],
  Gurmukhi: [0x0a15, 0x0a17],
  Gujarati: [0x0a95, 0x0a97],
  Oriya: [0x0b15, 0x0b17],
  Tamil: [0x0b95, 0x0b99],
  Telugu: [0x0c15, 0x0c17],
  Kannada: [0x0c95, 0x0c97],
  Malayalam: [0x0d15, 0x0d17],
  Sinhala: [0x0d9a, 0x0d9c],
};

describe("stripInvisible: ZWNJ/ZWJ linguistic carve-out", () => {
  for (const [name, sample, joinerAt] of [
    ["Persian ZWNJ between Arabic letters", PERSIAN, 2],
    ["Devanagari ZWJ between letters", DEVANAGARI, 2],
    ["emoji ZWJ family sequence", FAMILY, 2],
  ]) {
    it(`preserves ${name} unchanged`, () => {
      const { cleaned, found } = stripInvisibleWithReport(sample);
      assert.equal(cleaned, sample);
      assert.deepEqual(found, []);
      const code = cleaned.codePointAt(joinerAt);
      assert.ok(
        code === 0x200c || code === 0x200d,
        `join control gone: U+${code.toString(16)}`,
      );
    });
  }

  // Drive one preserve-case per script in LINGUISTIC_SCRIPTS (both joiners):
  // line coverage hits the whole character class on a single match (Arabic),
  // leaving the others unverified, so iterate the SSOT — a script added without
  // a representative-letter mapping throws here.
  for (const script of LINGUISTIC_SCRIPTS) {
    const letters = SCRIPT_LETTERS[script];
    assert.ok(
      letters,
      `no representative letters wired for script "${script}"`,
    );
    for (const joiner of [ZWNJ, ZWJ]) {
      const label = joiner === ZWNJ ? "ZWNJ" : "ZWJ";
      it(`preserves a ${label} between two ${script} letters`, () => {
        const sample = cp(letters[0]) + joiner + cp(letters[1]);
        const { cleaned, found } = stripInvisibleWithReport(sample);
        assert.equal(cleaned, sample);
        assert.deepEqual(found, []);
      });
    }
  }

  it("preserves a carve-out joiner after a leading BOM", () => {
    const { cleaned, found } = stripInvisibleWithReport(cp(0xfeff) + PERSIAN);
    assert.equal(cleaned, cp(0xfeff) + PERSIAN);
    assert.deepEqual(found, []);
  });

  it("preserves a skin-tone + ZWJ + component emoji sequence", () => {
    // 👨🏻‍🦰 = man + skin-tone modifier + ZWJ + red-hair component: the ZWJ has a
    // modifier on its left and a pictograph component on its right.
    const redHair = cp(0x1f468) + cp(0x1f3fb) + ZWJ + cp(0x1f9b0);
    const { cleaned, found } = stripInvisibleWithReport(redHair);
    assert.equal(cleaned, redHair);
    assert.deepEqual(found, []);
  });

  // Payload contexts: each is still stripped AND reported in `found`.
  for (const [name, input, expected] of [
    ["ZWNJ between Latin", `a${ZWNJ}b`, "ab"],
    ["ZWJ between Latin (no emoji on the left)", `a${ZWJ}b`, "ab"],
    [
      "ZWNJ with an Arabic left but a Latin right",
      `${cp(0x645)}${ZWNJ}x`,
      `${cp(0x645)}x`,
    ],
    [
      "leading ZWNJ before an Arabic letter",
      `${ZWNJ}${cp(0x645)}${cp(0x6cc)}`,
      `${cp(0x645)}${cp(0x6cc)}`,
    ],
    [
      "trailing ZWNJ after an Arabic letter",
      `${cp(0x645)}${cp(0x6cc)}${ZWNJ}`,
      `${cp(0x645)}${cp(0x6cc)}`,
    ],
    [
      "ZWJ with an emoji left but a non-emoji right",
      `${cp(0x1f468)}${ZWJ}x`,
      `${cp(0x1f468)}x`,
    ],
    [
      "ZWNJ between two emoji (ZWNJ never joins emoji)",
      `${cp(0x1f468)}${ZWNJ}${cp(0x1f469)}`,
      `${cp(0x1f468)}${cp(0x1f469)}`,
    ],
    [
      "a long ZWJ run between Arabic letters",
      `${cp(0x645)}${ZWJ.repeat(12)}${cp(0x62e)}`,
      `${cp(0x645)}${cp(0x62e)}`,
    ],
  ]) {
    it(`strips ${name} and reports it`, () => {
      const { cleaned, found } = stripInvisibleWithReport(input);
      assert.equal(cleaned, expected);
      assert.deepEqual(found, [CATEGORY.CF]);
    });
  }

  // The scatter floor (SCATTERED_THRESHOLD = 30) is a boundary on TOTAL
  // invisibles: 29 keep the carve-out enabled, 30 disable it wholesale. Both
  // sides are pinned so a `<`→`<=`/`>` mutant can't survive. To probe THIS gate
  // alone we hold the joiner count under TOTAL_PRESERVED_JOINER_BUDGET (so the
  // budget gate doesn't trip first) and pad the rest of the floor with a
  // non-joiner invisible class (interior BOMs) the budget never governs. A
  // single legit Persian word (1 ZWNJ) survives at 29 total, is stripped at 30.
  const padCount = SCATTERED_THRESHOLD - 2; // + 1 joiner = SCATTERED_THRESHOLD-1
  const interiorBom = cp(0xfeff); // Cf, strippable, NOT a joiner

  it(`keeps a legit joiner just under the scatter floor (${SCATTERED_THRESHOLD - 1} total)`, () => {
    const word = cp(0x645) + ZWNJ + cp(0x62e);
    // word ends, then a real visible char, then the BOM padding (interior BOMs
    // are stripped but counted toward the floor): 1 joiner + (floor-2) = floor-1.
    const input = word + "x" + interiorBom.repeat(padCount);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, word + "x"); // joiner preserved, interior BOMs gone
    assert.deepEqual(found, [CATEGORY.CF]); // the BOM padding is reported
    assert.equal(countOf(cleaned, ZWNJ), 1);
  });

  it("strips the joiner too once the scatter floor is reached", () => {
    const word = cp(0x645) + ZWNJ + cp(0x62e);
    // 1 joiner + (floor-1) BOMs = floor total → carve-out off, joiner stripped.
    const input = word + "x" + interiorBom.repeat(SCATTERED_THRESHOLD - 1);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, cp(0x645) + cp(0x62e) + "x");
    assert.deepEqual(found, [CATEGORY.CF]);
    assert.equal(countOf(cleaned, ZWNJ), 0);
  });

  it("counts EVERY invisible class toward the floor, not just joiners", () => {
    // 29 variation selectors + 1 ZWNJ = 30 total invisibles: the floor counts
    // all STRIP classes, so even an otherwise-legit Arabic ZWNJ is stripped.
    const input =
      cp(0xfe0f).repeat(SCATTERED_THRESHOLD - 1) + cp(0x645) + ZWNJ + cp(0x62e);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, cp(0x645) + cp(0x62e));
    assert.deepEqual(found, [CATEGORY.CF, CATEGORY.VARIATION_SELECTORS]);
  });

  it("keeps a legit joiner while stripping every other invisible class", () => {
    // Carve path (a joiner is present) must still strip the non-joiner classes —
    // a stray ZWSP (Cf), a variation selector, and a Hangul blank filler — and
    // report each category, while the Persian ZWNJ survives.
    const input =
      PERSIAN +
      cp(0x200b) + // ZWSP (Cf)
      `a${cp(0xfe0f)}b` + // VS-16
      `c${cp(0x3164)}d`; // Hangul filler
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, PERSIAN + "abcd");
    assert.deepEqual(found, [
      CATEGORY.CF,
      CATEGORY.VARIATION_SELECTORS,
      CATEGORY.BLANK_FILLERS,
    ]);
  });
});

// ─── isSgrOnly / SGR_RE ──────────────────────────────────────────────────────

describe("isSgrOnly", () => {
  it("is true when every ESC belongs to an SGR color sequence", () => {
    assert.equal(isSgrOnly(`${cp(0x1b)}[32mhello${cp(0x1b)}[0m`), true);
  });
  it("is true for text with no ESC at all", () =>
    assert.equal(isSgrOnly("plain text"), true));
  it("is false when a non-SGR escape (cursor move) is present", () =>
    assert.equal(isSgrOnly(`${cp(0x1b)}[2J`), false));
  it("is false for a lone/partial escape", () =>
    assert.equal(isSgrOnly(`${cp(0x1b)}[`), false));
  it("SGR_RE matches a color sequence", () =>
    assert.equal(`${cp(0x1b)}[31mx`.replace(SGR_RE, ""), "x"));

  // C1 (8-bit) encodings: a single U+009B (CSI) stands in for `ESC [`. isSgrOnly
  // must judge these exactly as their 7-bit twins, never letting a C1 introducer
  // pass unseen (the bug: an ESC-only test was blind to U+009B).
  it("is true for a C1-introduced SGR color sequence", () =>
    assert.equal(isSgrOnly(`${cp(0x9b)}31mhi${cp(0x9b)}0m`), true));
  it("is false for a C1-introduced cursor move", () =>
    assert.equal(isSgrOnly(`${cp(0x9b)}2J`), false));
  it("is false for a lone C1 CSI introducer", () =>
    assert.equal(isSgrOnly(cp(0x9b)), false));
  it("SGR_RE matches a C1-introduced color sequence", () =>
    assert.equal(`${cp(0x9b)}31mx`.replace(SGR_RE, ""), "x"));

  // C1 OSC (U+009D) is an Operating System Command string, not SGR. A residual
  // C1-OSC introducer must read as NOT SGR-only (the S1 residual: the test only
  // knew U+009B, so a string whose sole introducer was U+009D slipped through as
  // "SGR-only"). The paired SGR case stays true to prove the widening did not
  // over-reject genuine color.
  it("is false for a C1-OSC (U+009D) string", () =>
    assert.equal(isSgrOnly(`${cp(0x9d)}0;title${cp(0x07)}`), false));
  it("stays true for a genuine 7-bit SGR color string", () =>
    assert.equal(isSgrOnly(`${cp(0x1b)}[31mred${cp(0x1b)}[0m`), true));
});

// ─── LONG_RUN_RE ─────────────────────────────────────────────────────────────

describe("LONG_RUN_RE", () => {
  it(`matches a run of exactly LONG_RUN_THRESHOLD (${LONG_RUN_THRESHOLD}) invisibles`, () => {
    LONG_RUN_RE.lastIndex = 0;
    assert.equal(LONG_RUN_RE.test(cp(0x200b).repeat(LONG_RUN_THRESHOLD)), true);
  });
  it("does not match a run one short of the threshold", () => {
    LONG_RUN_RE.lastIndex = 0;
    assert.equal(
      LONG_RUN_RE.test(cp(0x200b).repeat(LONG_RUN_THRESHOLD - 1)),
      false,
    );
  });
});

// ─── Zero-width combining marks (Mn) ─────────────────────────────────────────
// These render with no advance width yet are category Mn, so \p{Cf} misses them
// and only the enumerated ZERO_WIDTH_MN set catches them. One case per member
// (drive off the SSOT so a dropped entry fails here), plus a guard that a
// VISIBLE combining mark is never swept.
describe("zero-width Mn marks", () => {
  for (const ch of ZERO_WIDTH_MN) {
    const hex = ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
    it(`strips zero-width Mn mark U+${hex}`, () => {
      const { cleaned, found } = stripInvisibleWithReport(`a${ch}b`);
      assert.equal(cleaned, "ab");
      assert.deepEqual(found, [CATEGORY.BLANK_FILLERS]);
    });
  }

  it("every ZERO_WIDTH_MN member is part of BLANK_NON_CF", () => {
    for (const ch of ZERO_WIDTH_MN) assert.ok(BLANK_NON_CF.includes(ch));
  });

  // U+0301 COMBINING ACUTE ACCENT has visible width — it must be left intact;
  // only zero-advance Mn marks are payload-capable.
  it("preserves a visible combining mark (U+0301)", () => {
    const input = `e${cp(0x0301)}`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });
});

// ─── Consecutive-joiner cap (hidden-channel collapse) ────────────────────────
// An attacker alternates `letter joiner letter joiner …` so every joiner is, in
// isolation, in a "linguistic" context AND the total stays under the scatter
// floor — a multi-bit zero-width channel that survived both clean and scan. The
// cap collapses it: at most CONSECUTIVE_JOINER_CAP joiners survive in one
// uninterrupted joined run, the surplus stripped as payload.
describe("consecutive-joiner cap", () => {
  const AR1 = cp(0x645);
  const AR2 = cp(0x62e);

  it(`caps preserved ZWNJ in an alternating Arabic run at ${CONSECUTIVE_JOINER_CAP}`, () => {
    const input = (AR1 + ZWNJ).repeat(CONSECUTIVE_JOINER_CAP + 12) + AR2;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(countOf(cleaned, ZWNJ), CONSECUTIVE_JOINER_CAP);
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it(`caps preserved ZWJ in an alternating emoji run at ${CONSECUTIVE_JOINER_CAP}`, () => {
    const input =
      cp(0x1f468) + (ZWJ + cp(0x1f469)).repeat(CONSECUTIVE_JOINER_CAP + 12);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(countOf(cleaned, ZWJ), CONSECUTIVE_JOINER_CAP);
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it("preserves exactly CONSECUTIVE_JOINER_CAP joiners (boundary, none stripped)", () => {
    const input = (AR1 + ZWNJ).repeat(CONSECUTIVE_JOINER_CAP) + AR2;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });

  it("a single linguistic joiner per word is preserved (cap resets at a gap)", () => {
    const word = AR1 + ZWNJ + AR2;
    const input = `${word} ${word} ${word}`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });

  it("the four-person family emoji (3 ZWJ) is under the cap and preserved", () => {
    const { cleaned, found } = stripInvisibleWithReport(FAMILY);
    assert.equal(cleaned, FAMILY);
    assert.deepEqual(found, []);
    assert.equal(countOf(cleaned, ZWJ), 3);
  });
});

// ─── Document-wide preserved-joiner budget (covert-channel collapse) ──────────
// The consecutive cap resets at every genuine gap, so an attacker who puts each
// joiner in its OWN cluster — `letter joiner letter letter` repeated, double
// letters forming the gap that resets joinerRun — preserves one joiner per
// cluster, threading an arbitrary number through while each sits in a per-char
// "linguistic" context AND the total stays under the scatter floor. That was a
// silent multi-bit zero-width channel: every joiner preserved, `found` empty.
// TOTAL_PRESERVED_JOINER_BUDGET caps the document-wide preserved count (never
// reset at a gap): the surplus is stripped AND reported.
describe("document-wide preserved-joiner budget", () => {
  const AR1 = cp(0x645);
  const AR2 = cp(0x62e);

  // One joiner per cluster, clusters separated by a double-letter gap so the
  // consecutive cap (per-cluster) never trips — only the document-wide budget
  // can catch this. N joiners chosen above the budget but below the scatter
  // floor (so the floor is NOT what trips), proving the budget is the gate.
  const N = TOTAL_PRESERVED_JOINER_BUDGET + 9; // 25 — the PoC payload size
  assert.ok(
    N < SCATTERED_THRESHOLD,
    "covert-channel case must stay under the scatter floor",
  );
  // cluster = `letter joiner letter` then a second letter as the gap opener.
  const cluster = AR1 + ZWNJ + AR2 + AR2;
  const covert = cluster.repeat(N);

  it("caps preserved joiners at the budget across separated clusters", () => {
    const { cleaned, found } = stripInvisibleWithReport(covert);
    assert.equal(countOf(covert, ZWNJ), N); // input really has N joiners
    assert.equal(
      countOf(cleaned, ZWNJ),
      TOTAL_PRESERVED_JOINER_BUDGET,
      "preserved joiner count must not exceed the budget",
    );
    assert.deepEqual(found, [CATEGORY.CF]); // the surplus strip is reported
  });

  it("alternating ZWNJ/ZWJ between Arabic letters is capped and flagged", () => {
    // Closest to the literal PoC: N alternating joiners, each between two Arabic
    // letters, clusters gap-separated. Mix the two joiner code points to prove
    // the budget counts both.
    let s = "";
    for (let k = 0; k < N; k++) {
      const j = k % 2 === 0 ? ZWNJ : ZWJ;
      s += AR1 + j + AR2 + AR2;
    }
    const { cleaned, found } = stripInvisibleWithReport(s);
    const preserved = countOf(cleaned, ZWNJ) + countOf(cleaned, ZWJ);
    assert.equal(preserved, TOTAL_PRESERVED_JOINER_BUDGET);
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it("preserves exactly the budget at the boundary (none stripped, not flagged)", () => {
    // Exactly TOTAL_PRESERVED_JOINER_BUDGET joiners, one per gap-separated
    // cluster: all preserved, nothing reported. Pins the `<` boundary so a
    // `<`→`<=` mutant (off-by-one over-strip) dies here.
    const input = cluster.repeat(TOTAL_PRESERVED_JOINER_BUDGET);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
    assert.equal(countOf(cleaned, ZWNJ), TOTAL_PRESERVED_JOINER_BUDGET);
  });

  it("the budget sits below the scatter floor so it is the operative gate", () => {
    assert.ok(TOTAL_PRESERVED_JOINER_BUDGET < SCATTERED_THRESHOLD);
  });
});

// ─── Precision negatives: real multilingual text is preserved un-flagged ──────
// The budget must NOT mangle or flag legitimate short multilingual content. A
// handful of genuine joiners — a Persian/Indic compound word, an emoji ZWJ
// sequence — stay byte-identical with an empty `found`.
describe("budget precision: legitimate joiners preserved and un-flagged", () => {
  // A short compound per script (1 joiner) plus a longer one (3 joiners): all
  // well under the budget, so none is stripped or flagged. Driven off the
  // LINGUISTIC_SCRIPTS SSOT so a new script without representative letters fails.
  const SCRIPT_LETTERS = {
    Arabic: [0x645, 0x62e],
    Devanagari: [0x915, 0x937],
    Bengali: [0x995, 0x99a],
    Gurmukhi: [0x0a15, 0x0a17],
    Gujarati: [0x0a95, 0x0a97],
    Oriya: [0x0b15, 0x0b17],
    Tamil: [0x0b95, 0x0b99],
    Telugu: [0x0c15, 0x0c17],
    Kannada: [0x0c95, 0x0c97],
    Malayalam: [0x0d15, 0x0d17],
    Sinhala: [0x0d9a, 0x0d9c],
  };
  for (const script of LINGUISTIC_SCRIPTS) {
    const [a, b] = SCRIPT_LETTERS[script];
    assert.ok(a !== undefined, `no representative letters for ${script}`);
    it(`a 1-3 joiner ${script} compound is preserved un-flagged`, () => {
      // " word1 word2 " with 1 then 3 joiners — 4 joiners total, under budget.
      const w1 = cp(a) + ZWNJ + cp(b);
      const w2 = cp(a) + ZWNJ + cp(b) + ZWNJ + cp(a) + ZWNJ + cp(b);
      const input = `${w1} ${w2}`;
      const { cleaned, found } = stripInvisibleWithReport(input);
      assert.equal(cleaned, input);
      assert.deepEqual(found, []);
    });
  }

  it("a family emoji ZWJ sequence is preserved un-flagged", () => {
    const { cleaned, found } = stripInvisibleWithReport(FAMILY);
    assert.equal(cleaned, FAMILY);
    assert.deepEqual(found, []);
  });

  it("several distinct emoji ZWJ sequences together stay under budget", () => {
    // Three family emoji (9 ZWJ total) separated by spaces: a realistic message,
    // still under the 16-joiner budget — preserved verbatim, no flag.
    const input = `${FAMILY} ${FAMILY} ${FAMILY}`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });
});

// ─── Layer 1: OSC strings + C1 sequences (no payload survives) ────────────────
// OSC strings carry attacker-controlled text (titles, hyperlink URLs) between an
// introducer and a terminator. The fix consumes the WHOLE string for every
// terminator form (ST `ESC\`, C1 ST U+009C, legacy BEL) and for the 8-bit C1
// OSC introducer, and drops an unterminated introducer's remainder (fail-closed).
describe("applyLayer1: OSC strings and C1 sequences", () => {
  const ESC = cp(0x1b);
  const BEL = cp(0x07);
  const ST = ESC + "\\";
  const C1_ST = cp(0x9c);
  const C1_OSC = cp(0x9d);
  const C1_CSI = cp(0x9b);

  for (const [name, input, expected] of [
    [
      "OSC title terminated by ST (ESC\\)",
      `before${ESC}]0;TITLE${ST}after`,
      "beforeafter",
    ],
    [
      "OSC title terminated by C1 ST",
      `before${ESC}]0;TITLE${C1_ST}after`,
      "beforeafter",
    ],
    [
      "OSC title terminated by BEL",
      `before${ESC}]0;TITLE${BEL}after`,
      "beforeafter",
    ],
    [
      "OSC hyperlink (URL payload) terminated by ST",
      `${ESC}]8;;https://evil/leak${ST}`,
      "",
    ],
    ["unterminated OSC consumes to end-of-string", `${ESC}]0;UNTERMINATED`, ""],
    [
      "C1 OSC introducer (U+009D) terminated by C1 ST",
      `x${C1_OSC}0;SECRET${C1_ST}y`,
      "xy",
    ],
    ["C1 OSC introducer terminated by ST", `x${C1_OSC}0;SECRET${ST}y`, "xy"],
    ["C1 CSI SGR color sequence", `a${C1_CSI}31mred${C1_CSI}0mb`, "aredb"],
    ["C1 CSI cursor/erase sequence", `a${C1_CSI}2Jb`, "ab"],
  ]) {
    it(`removes the whole sequence: ${name}`, () => {
      const { cleaned } = applyLayer1(input);
      assert.equal(cleaned, expected);
    });
  }

  it("leaves no raw control introducer for any of the OSC/C1 cases", () => {
    for (const input of [
      `${ESC}]0;t${ST}`,
      `${ESC}]0;t${C1_ST}`,
      `${ESC}]0;t${BEL}`,
      `${ESC}]0;unterminated`,
      `${C1_OSC}0;t${C1_ST}`,
      `${C1_CSI}31mx${C1_CSI}0m`,
    ]) {
      const { cleaned } = applyLayer1(input);
      assert.ok(!cleaned.includes(cp(0x1b)), "ESC survived");
      assert.ok(!cleaned.includes(cp(0x9b)), "C1 CSI survived");
      assert.ok(!cleaned.includes(cp(0x9d)), "C1 OSC survived");
    }
  });

  // The deliberate bounded-intro / negated-body design keeps the ANSI grammar
  // linear; an adversarial never-completing string must not blow up. Assert the
  // work scales ~linearly (not super-linearly) with input size.
  it("OSC/CSI stripping stays ~linear on adversarial never-terminating input", () => {
    const time = (n) => {
      const input = `${ESC}]` + ";".repeat(n) + `${ESC}[` + ";#".repeat(n);
      const t0 = process.hrtime.bigint();
      applyLayer1(input);
      return Number(process.hrtime.bigint() - t0);
    };
    // Warm up, then compare 10x size: linear ⇒ ratio well under quadratic (100x).
    time(2000);
    const small = Math.max(time(20000), 1);
    const big = time(200000);
    assert.ok(
      big / small < 40,
      `super-linear scaling: ${small}ns -> ${big}ns (ratio ${(big / small).toFixed(1)})`,
    );
  });
});

// ─── Property tests over the real input domain ───────────────────────────────

// Any single code point except the surrogate range (so .map(fromCodePoint)
// never throws); lone surrogates are injected separately.
const unicodeChar = fc
  .integer({ min: 0, max: 0x10ffff })
  .filter((c) => c < 0xd800 || c > 0xdfff)
  .map((c) => String.fromCodePoint(c));
const loneSurrogate = fc
  .integer({ min: 0xd800, max: 0xdfff })
  .map((c) => String.fromCharCode(c));
// Every invisible class, joiner-using script letters, emoji parts, ASCII.
const invisibleChar = fc.constantFrom(
  ...Array.from(BLANK_NON_CF),
  ...Array.from(VS),
  cp(0x200b),
  cp(0x200c),
  cp(0x200d),
  cp(0x00ad),
  cp(0xfeff),
  cp(0x2060),
);
const scriptChar = fc.constantFrom(
  cp(0x645),
  cp(0x62e),
  cp(0x915),
  cp(0x937),
  cp(0x1f468),
  cp(0x1f469),
  cp(0x1f3fb),
  "a",
  "Z",
  " ",
);
const adversarialChar = fc.oneof(
  unicodeChar,
  loneSurrogate,
  invisibleChar,
  scriptChar,
);
const adversarialText = fc
  .array(adversarialChar, { maxLength: 80 })
  .map((parts) => parts.join(""));

describe("property: stripInvisible invariants", () => {
  it("never throws on lone surrogates / astral input", () => {
    fc.assert(
      fc.property(adversarialText, (text) => {
        assert.equal(typeof stripInvisible(text), "string");
      }),
      fcRunOptions(),
    );
  });

  it("is idempotent: strip(strip(x)) === strip(x)", () => {
    fc.assert(
      fc.property(adversarialText, (text) => {
        const once = stripInvisible(text);
        assert.equal(stripInvisible(once), once);
      }),
      fcRunOptions(),
    );
  });

  it("output is a subsequence of the input (deletion only)", () => {
    fc.assert(
      fc.property(adversarialText, (text) => {
        // Compared at the UTF-16 code-UNIT level, not code points: deleting a
        // char between two lone surrogates can join them into a valid astral
        // pair, so the property holds per code unit but not per code point.
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

  it("`found` is exactly the set of categories that actually changed the text", () => {
    fc.assert(
      fc.property(adversarialText, (text) => {
        const { cleaned, found } = stripInvisibleWithReport(text);
        // Every reported category must really be a CHECKS code.
        const codes = new Set(CHECKS.map(([code]) => code));
        for (const f of found) assert.ok(codes.has(f), `bogus code: ${f}`);
        // found non-empty ⇔ the text changed (a strip happened). A preserved
        // joiner leaves text === cleaned AND found empty.
        assert.equal(found.length > 0, cleaned !== text);
      }),
      fcRunOptions(),
    );
  });

  it("a BOM is preserved only when leading", () => {
    fc.assert(
      fc.property(adversarialText, (text) => {
        const cleaned = stripInvisible(text);
        const hadLeadingBom = text.charCodeAt(0) === 0xfeff;
        // No interior BOM ever survives.
        const interior = cleaned.slice(1);
        assert.ok(!interior.includes(cp(0xfeff)), "interior BOM survived");
        // A leading BOM survives iff the input led with one.
        assert.equal(cleaned.charCodeAt(0) === 0xfeff, hadLeadingBom);
      }),
      fcRunOptions(),
    );
  });

  it("STRIP-matchable chars are gone unless preserved by the carve-out", () => {
    fc.assert(
      fc.property(adversarialText, (text) => {
        const cleaned = stripInvisible(text);
        // After stripping, the only STRIP-class chars left must be ZWNJ/ZWJ
        // (carve-out) or a single leading BOM.
        for (let i = 0; i < cleaned.length; i++) {
          const ch = cleaned[i];
          STRIP.lastIndex = 0;
          if (!STRIP.test(ch)) continue;
          const code = cleaned.codePointAt(i);
          const ok =
            code === 0x200c || code === 0x200d || (code === 0xfeff && i === 0);
          assert.ok(ok, `unexpected residual invisible U+${code.toString(16)}`);
        }
      }),
      fcRunOptions(),
    );
  });
});

// applyLayer1 over a domain that ALSO includes raw ANSI introducers/terminators
// (ESC, C1 CSI/OSC/ST, BEL, `[`, `]`, `;`, `m`) so the property exercises the
// OSC/CSI grammar, not just invisible chars.
const ansiChar = fc.constantFrom(
  cp(0x1b),
  cp(0x9b),
  cp(0x9c),
  cp(0x9d),
  cp(0x07),
  "[",
  "]",
  ";",
  "m",
  "0",
);
const layer1Text = fc
  .array(fc.oneof(adversarialChar, ansiChar), { maxLength: 80 })
  .map((parts) => parts.join(""));

describe("property: applyLayer1 invariants", () => {
  it("never throws on adversarial ANSI + invisible + surrogate input", () => {
    fc.assert(
      fc.property(layer1Text, (text) => {
        const { cleaned } = applyLayer1(text);
        assert.equal(typeof cleaned, "string");
      }),
      fcRunOptions(),
    );
  });

  it("no raw ANSI control introducer (ESC / C1 CSI) survives, for any input", () => {
    fc.assert(
      fc.property(layer1Text, (text) => {
        const { cleaned } = applyLayer1(text);
        assert.ok(!cleaned.includes(cp(0x1b)), "ESC survived");
        assert.ok(!cleaned.includes(cp(0x9b)), "C1 CSI survived");
      }),
      fcRunOptions(),
    );
  });

  it("is idempotent: applyLayer1(applyLayer1(x)) === applyLayer1(x)", () => {
    fc.assert(
      fc.property(layer1Text, (text) => {
        const once = applyLayer1(text).cleaned;
        assert.equal(applyLayer1(once).cleaned, once);
      }),
      fcRunOptions(),
    );
  });
});
