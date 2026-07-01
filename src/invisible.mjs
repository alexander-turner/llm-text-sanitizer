/**
 * Pure, zero-dependency invisible-character + ANSI/SGR primitives.
 *
 * Removes payload-capable Unicode (general-category Cf format chars, variation
 * selectors, blank-rendering fillers, soft hyphens, interior BOMs) while
 * preserving ZWNJ/ZWJ in genuine linguistic and emoji contexts, and reports
 * which categories were removed.
 */

export const VS = [
  ...Array.from({ length: 16 }, (_, i) => 0xfe00 + i),
  ...Array.from({ length: 240 }, (_, i) => 0xe0100 + i),
]
  .map((codePoint) => String.fromCodePoint(codePoint))
  .join("");

// Combining marks (general category Mn) that carry NO advance width \u2014 they
// render as nothing on their own, so a run of them is a hidden channel exactly
// like a zero-width Cf char, yet \p{Cf} misses them (they are Mn). Strictly
// enumerated, one reason per entry, because MOST Mn marks DO have visible width
// (accents, vowel signs) and must never be stripped \u2014 only these zero-advance
// ones qualify. Driven as an SSOT so the test iterates one case per member.
//   U+034F COMBINING GRAPHEME JOINER \u2014 invisible; affects only collation/shaping
//   U+17B4 KHMER VOWEL INHERENT AQ   \u2014 zero-width inherent vowel, renders blank
//   U+17B5 KHMER VOWEL INHERENT AA   \u2014 zero-width inherent vowel, renders blank
export const ZERO_WIDTH_MN = "\u034F\u17B4\u17B5";

// Code points that render blank / zero-width but are NOT general category Cf,
// so the \p{Cf} check below misses them: the Hangul fillers (category Lo,
// U+115F/U+1160/U+3164/U+FFA0), the Braille blank pattern (category So,
// U+2800), and the zero-width combining marks above (category Mn). A run of any
// of these carries a hidden payload exactly as zero-widths do.
export const BLANK_NON_CF = "\u115F\u1160\u3164\uFFA0\u2800" + ZERO_WIDTH_MN;

const REGEX_FLAGS = "gu";

// Stable, machine-readable category codes for the `found` array returned by
// stripInvisibleWithReport and sanitize. These are API: branch on them. They
// are deliberately NOT the human-facing prose (that lives in `warnings` and in
// CATEGORY_LABELS), so the display wording can be reworded without a breaking
// change to anyone matching on `found`.
export const CATEGORY = Object.freeze({
  CF: "cf-format",
  VARIATION_SELECTORS: "variation-selectors",
  BLANK_FILLERS: "blank-fillers",
  ANSI: "ansi",
  LONE_SURROGATES: "lone-surrogates",
  HTML_COMMENTS: "html-comments",
  HIDDEN_HTML: "hidden-html",
  EXFIL_URLS: "exfil-urls",
});

// code -> human label, used only to build `warnings` text. Decoupled from
// CATEGORY so prose changes never alter the machine-readable `found` contract.
/** @type {Readonly<Record<string, string>>} */
export const CATEGORY_LABELS = Object.freeze({
  [CATEGORY.CF]: "Format chars (Cf)",
  [CATEGORY.VARIATION_SELECTORS]: "Variation selectors",
  [CATEGORY.BLANK_FILLERS]: "Blank-rendering fillers",
  [CATEGORY.ANSI]: "ANSI escapes",
  [CATEGORY.LONE_SURROGATES]: "Lone UTF-16 surrogates",
  [CATEGORY.HTML_COMMENTS]: "HTML comments",
  [CATEGORY.HIDDEN_HTML]: "hidden HTML",
  [CATEGORY.EXFIL_URLS]: "exfil URLs",
});

/** @type {Array<[string, RegExp]>} Each entry pairs a CATEGORY code with its detector. */
export const CHECKS = [
  [CATEGORY.CF, new RegExp(`\\p{Cf}`, REGEX_FLAGS)],
  [CATEGORY.VARIATION_SELECTORS, new RegExp(`[${VS}]`, REGEX_FLAGS)],
  // BLANK_NON_CF includes zero-width COMBINING marks (Mn: U+034F/17B4/17B5). In
  // a `u`-flag class each matches its own single code point — exactly the intent
  // (we strip the lone mark, never a base+mark grapheme), so the
  // misleading-character-class heuristic is a false positive here.
  // eslint-disable-next-line no-misleading-character-class -- single-code-point matches under the u flag are intentional
  [CATEGORY.BLANK_FILLERS, new RegExp(`[${BLANK_NON_CF}]`, REGEX_FLAGS)],
];

export const STRIP = new RegExp(
  CHECKS.map(([, regex]) => regex.source).join("|"),
  REGEX_FLAGS,
);

// SGR (Select Graphic Rendition): colors, bold, reset. The grammar is closed:
// params are [0-9;]* and the final byte is `m`, so a match can only restyle
// text, never reposition the cursor, erase, or smuggle an OSC string. A SGR
// sequence has TWO encodings: the 7-bit `ESC [ … m` and the 8-bit C1 form where
// a single U+009B (CSI) replaces `ESC [`. Both must be recognized — otherwise a
// C1-introduced `U+009B 31m … 0m` is pure color yet is misread as a non-SGR
// payload (or, worse, mistaken for SGR-only when its introducer was a C1 CSI
// that isSgrOnly's ESC-only test never saw). Text is "SGR-only" when removing
// these leaves no ANSI control introducer at all — a lone or partial escape is
// therefore not SGR-only.
// eslint-disable-next-line no-control-regex -- matching ESC-led sequences is the point
export const SGR_RE = /(?:\x1b\[|)[0-9;]*m/g;

// The raw ANSI control introducers isSgrOnly must treat as NON-SGR after SGR
// removal: 7-bit ESC (U+001B) and the entire 8-bit C1 control block
// (U+0080–U+009F) — CSI (U+009B), the DCS/SOS/OSC/PM/APC string introducers, and
// ST. isSgrOnly is honest only if it tests for ALL of them — a C1 cursor-move or
// erase (`U+009B 2J`) leaves a U+009B, a C1-OSC string (`U+009D … BEL`) leaves a
// U+009D, and a C1-DCS/APC payload (`U+0090 … ST`) leaves its introducer, after
// SGR removal; each must read as NOT SGR-only, exactly as their 7-bit `ESC[2J` /
// `ESC]…` / `ESC P…` twins do. Omitting any would let a residual C1 introducer
// be misread as SGR-only.
// eslint-disable-next-line no-control-regex -- the raw introducers are what we test for
const CONTROL_INTRODUCER_RE = /[\x1b\u0080-\u009f]/;

/**
 * True when every ANSI control introducer in `text` belongs to a display-only
 * SGR color sequence (so stripping the ANSI removed only cosmetic styling,
 * nothing that could move the cursor, erase, or carry a payload). Recognizes
 * both the 7-bit `ESC[…m` and 8-bit C1 (`U+009B…m`) SGR encodings.
 * @param {string} text
 * @returns {boolean}
 */
export function isSgrOnly(text) {
  return !CONTROL_INTRODUCER_RE.test(text.replace(SGR_RE, ""));
}

export const LONG_RUN_THRESHOLD = 10;

/** Total invisible-char count above which a file/prompt is treated as
 * payload-capable even without a long run (threshold-evasion catch). */
export const SCATTERED_THRESHOLD = 30;

export const LONG_RUN_RE = new RegExp(
  `(?:${STRIP.source}){${LONG_RUN_THRESHOLD},}`,
  REGEX_FLAGS,
);

/**
 * The agent-facing "Stripped: …" note for a Layer-1 strip: the removed category
 * labels, the LONG RUN marker when the de-ANSI'd text still holds a
 * payload-length invisible run, and a pointer to recover the bytes — a hex dump
 * is ASCII, so it passes through sanitization untouched. The single source of
 * this note, shared by the `sanitize` convenience entry and the tool-output
 * pipeline so the two can't drift.
 * @param {string[]} invisFound CATEGORY codes applyLayer1 reported removing
 * @param {string} deAnsi ANSI-stripped text (invisible runs intact), for the LONG_RUN probe
 * @returns {string}
 */
export function describeStripped(invisFound, deAnsi) {
  let msg = `Stripped: ${invisFound.map((code) => CATEGORY_LABELS[code]).join(", ")}`;
  LONG_RUN_RE.lastIndex = 0;
  if (LONG_RUN_RE.test(deAnsi))
    msg += " [LONG RUN — possible injection payload]";
  return (
    msg +
    " — inspect the removed bytes with a hex dump (xxd / od -c), which survives sanitization"
  );
}

// Leading-BOM marker, preserved by stripInvisibleWithReport (see its doc).
const BOM = "\uFEFF";
// ─── ZWNJ/ZWJ linguistic carve-out ───────────────────────────────────────────
// ZWNJ (U+200C) and ZWJ (U+200D) are general category Cf, so the STRIP pass
// would treat them as hidden-payload bytes. But they are MANDATORY for correct
// rendering between letters of several scripts (Arabic/Persian and many Indic
// scripts) and inside emoji ZWJ sequences — blanket stripping corrupts
// legitimate non-English output. Preserve them ONLY in an unambiguous
// linguistic context (immediately between two letters of such a script, or
// between two members of an emoji ZWJ sequence) and strip them as a payload
// everywhere else: a long run, scattered past SCATTERED_THRESHOLD, a
// leading/trailing position, or between Latin/ASCII/secret-shaped characters.
// Over-strip beats under-strip — the carve-out fires only when BOTH neighbors
// clearly belong to the context.
const ZWNJ = 0x200c;
const ZWJ = 0x200d;

// Max joiners the carve-out will PRESERVE within one uninterrupted joined
// sequence (a `letter (joiner letter)*` run, or an emoji ZWJ sequence). A real
// word or emoji glyph needs only a handful in a row — the longest standard emoji
// ZWJ sequences (family-of-four, profession+ZWJ) carry three; a Persian
// compound a couple. Past this many consecutive PRESERVED joiners with no real
// gap between them, the run is treated as a zero-width payload channel (an
// attacker alternates `letter joiner letter joiner …` to stay both under the
// scatter floor AND in a per-joiner "linguistic" context) and the surplus
// joiners are stripped. The counter resets at any genuine gap — two visible
// characters in a row, i.e. text that is NOT part of a joined cluster — so an
// ordinary single linguistic/emoji joiner per word is always preserved.
export const CONSECUTIVE_JOINER_CAP = 8;

// Max joiners the carve-out will PRESERVE across the WHOLE string, summed over
// every cluster (unlike CONSECUTIVE_JOINER_CAP, this counter never resets at a
// gap). It closes a covert channel the consecutive cap alone leaves open: an
// attacker writes `letter joiner letter letter` repeatedly so each joiner sits
// between two linguistic letters (preserved) and every cluster is separated by a
// real gap (resetting joinerRun), threading many one-bit joiners through while
// staying under SCATTERED_THRESHOLD — so the consecutive cap never trips and
// `found` stays empty. A document-wide budget catches the aggregate: once more
// than this many joiners would be preserved, the surplus is stripped as payload
// AND the category is reported, so the result is never silently carrying a large
// hidden joiner channel.
//
// Sizing (precision over recall — err toward preserving real text): the scatter
// floor already caps TOTAL invisibles at SCATTERED_THRESHOLD (30); above it the
// carve-out is off and every joiner is stripped. So the only joiners this budget
// governs are those in texts with fewer than 30 total invisibles. Within that
// window, legitimate multilingual prose stays well under 16: a Persian sentence
// carries a handful of ZWNJ, the longest standard emoji ZWJ sequences three.
// Genuine text dense enough to need >16 joiners would also push total invisibles
// past the scatter floor and be handled there. 16 sits comfortably above real
// usage yet well under the 25-joiner PoC, so honest text is preserved un-flagged
// while a stuffed channel is capped and surfaced.
export const TOTAL_PRESERVED_JOINER_BUDGET = 16;

// Scripts whose orthography uses ZWNJ/ZWJ between letters as a rendering
// control. Single source of truth: LINGUISTIC_LETTER is built from this list,
// and the test suite drives one preserve-case per entry, so adding a script
// here without a matching test fails.
export const LINGUISTIC_SCRIPTS = [
  "Arabic",
  "Devanagari",
  "Bengali",
  "Gurmukhi",
  "Gujarati",
  "Oriya",
  "Tamil",
  "Telugu",
  "Kannada",
  "Malayalam",
  "Sinhala",
];
const LINGUISTIC_LETTER = new RegExp(
  `[${LINGUISTIC_SCRIPTS.map((script) => `\\p{Script=${script}}`).join("")}]`,
  "u",
);
// Left side of an emoji joiner: a pictograph or a skin-tone modifier (a base
// emoji may carry a modifier before the joiner, e.g. a health-worker sequence).
const EMOJI_LEFT = /[\p{Extended_Pictographic}\p{Emoji_Modifier}]/u;
// Right side of an emoji joiner is always the next component's base pictograph.
const EMOJI_BASE = /\p{Extended_Pictographic}/u;
// A variation selector legitimately sits between a base pictograph and a
// following ZWJ (🏳️‍🌈 = flag base, VS16, ZWJ, rainbow; 👁️‍🗨️), so the joiner's real
// left neighbor for the emoji test is the pictograph, not the selector.
const VARIATION_SELECTOR = new RegExp(`[${VS}]`, "u");
// U+FE0F forces emoji (vs text) presentation; a single one directly after a
// pictograph is part of a visible emoji, not a hidden variation-selector run.
const EMOJI_PRESENTATION_SELECTOR = 0xfe0f;

// Non-global single-char classifiers (CHECKS carry `g`, whose lastIndex is
// stateful across `.test`). carveStrip uses these to attribute each removed
// char to its CHECKS category so `found` names exactly what was stripped.
const CHECK_ONE = CHECKS.map(
  ([code, re]) =>
    /** @type {[string, RegExp]} */ ([code, new RegExp(re.source, "u")]),
);

/**
 * The CHECKS category code (a CATEGORY value) a single code point belongs to,
 * or null when it is not payload-capable (an ordinary visible character).
 * @param {string} ch  one code point
 * @returns {string | null}
 */
function classify(ch) {
  for (const [code, re] of CHECK_ONE) if (re.test(ch)) return code;
  return null;
}

/**
 * True when `ch` (a ZWNJ/ZWJ) sits in an unambiguous linguistic context and so
 * must be preserved rather than stripped. `prev`/`next` are the adjacent code
 * points (single-code-point strings), or "" at a string boundary.
 * @param {string} ch
 * @param {string} prev
 * @param {string} next
 * @returns {boolean}
 */
function isPreservedJoiner(ch, prev, next) {
  const cp = ch.codePointAt(0);
  if (cp !== ZWNJ && cp !== ZWJ) return false;
  // prev/next are "" at a string boundary (see carveStrip), so a leading or
  // trailing joiner matches neither script nor emoji class and falls through.
  if (LINGUISTIC_LETTER.test(prev) && LINGUISTIC_LETTER.test(next)) return true;
  // Emoji ZWJ sequences use ZWJ only, never ZWNJ.
  if (cp === ZWJ && EMOJI_LEFT.test(prev) && EMOJI_BASE.test(next)) return true;
  return false;
}

/**
 * Bulk strip (the common path: no ZWNJ/ZWJ present, so no carve-out can apply).
 * A single regex pass removes every payload-capable char; `found` names the
 * category codes present via `.search` (which ignores the `g` lastIndex).
 * @param {string} body
 * @returns {{ cleaned: string, found: string[] }}
 */
function bulkStrip(body) {
  const found = CHECKS.filter(([, re]) => body.search(re) !== -1).map(
    ([code]) => code,
  );
  return { cleaned: body.replace(STRIP, ""), found };
}

/**
 * The nearest code point left of index `i` that is not a variation selector, or
 * "" at the string start. An emoji ZWJ sequence can place a VS16 between the base
 * pictograph and the ZWJ, so the joiner's real left neighbor is found by stepping
 * over any variation selector(s).
 * @param {string[]} cps
 * @param {number} i
 * @returns {string}
 */
function leftNonSelector(cps, i) {
  let p = i - 1;
  while (p >= 0 && VARIATION_SELECTOR.test(cps[p])) p--;
  return cps[p] ?? "";
}

/**
 * Carve-out strip (a ZWNJ/ZWJ is present): walk code points, preserving a join
 * control only where isPreservedJoiner holds AND the text stays under the
 * scatter floor AND neither the per-cluster (CONSECUTIVE_JOINER_CAP) nor the
 * document-wide (TOTAL_PRESERVED_JOINER_BUDGET) preserve limit is hit —
 * otherwise it is stripped like any other payload byte. `found` reports only
 * categories actually removed, so a preserved joiner never makes the caller
 * claim a strip that did not happen, and a stuffed joiner channel surfaces as
 * CATEGORY.CF once it overruns the budget.
 * @param {string} body
 * @returns {{ cleaned: string, found: string[] }}
 */
function carveStrip(body) {
  // SCATTERED_THRESHOLD is the floor: past it, treat every invisible as payload
  // regardless of context (threshold-evasion catch — over-strip beats under).
  // Materialise codepoints once; count invisibles in a first pass so we know
  // whether the carve-out applies before building the output string.
  const cps = Array.from(body);
  let invisCount = 0;
  for (const ch of cps) if (classify(ch) !== null) invisCount++;
  const allowCarveOut = invisCount < SCATTERED_THRESHOLD;
  const foundCodes = new Set();
  let out = "";
  // Joiners preserved so far in the current uninterrupted joined sequence. A
  // genuine gap (two visible chars in a row — see prevVisible) resets it to 0;
  // once it would exceed the cap the surplus joiners are stripped as payload.
  let joinerRun = 0;
  // Joiners preserved so far across the WHOLE string — never reset at a gap, so
  // it caps the document-wide channel the per-cluster joinerRun cannot (see
  // TOTAL_PRESERVED_JOINER_BUDGET). Past the budget a joiner is stripped and its
  // category reported, even though it is in a per-char linguistic context.
  let preservedTotal = 0;
  let prevVisible = false;
  for (let i = 0; i < cps.length; i++) {
    const ch = cps[i];
    const code = classify(ch);
    if (code === null) {
      // A visible char following another visible char is a real word/segment
      // boundary, not a join — the joined cluster (if any) ended here.
      if (prevVisible) joinerRun = 0;
      prevVisible = true;
      out += ch; // ordinary visible character
      continue;
    }
    const underBudget =
      allowCarveOut && preservedTotal < TOTAL_PRESERVED_JOINER_BUDGET;
    // An emoji presentation selector (U+FE0F) directly after a pictograph or
    // skin-tone modifier is part of a visible emoji, not a hidden VS run — keep
    // it so an emoji ZWJ sequence survives intact. A genuine variation-selector
    // run still surfaces: only the selector adjacent to the pictograph is
    // preserved; the next one's left neighbor is itself a selector, so it is
    // stripped and reported. Counts against the document budget like a joiner.
    if (
      underBudget &&
      ch.codePointAt(0) === EMOJI_PRESENTATION_SELECTOR &&
      EMOJI_LEFT.test(cps[i - 1] ?? "")
    ) {
      preservedTotal++;
      prevVisible = false; // the selector keeps the emoji cluster open
      out += ch;
      continue;
    }
    if (
      underBudget &&
      joinerRun < CONSECUTIVE_JOINER_CAP &&
      isPreservedJoiner(ch, leftNonSelector(cps, i), cps[i + 1] ?? "")
    ) {
      joinerRun++;
      preservedTotal++;
      prevVisible = false; // a joiner keeps the cluster open
      out += ch;
      continue;
    }
    foundCodes.add(code);
    prevVisible = false; // a stripped invisible neither opens nor closes a gap
  }
  const found = CHECKS.filter(([code]) => foundCodes.has(code)).map(
    ([code]) => code,
  );
  return { cleaned: out, found };
}

/**
 * True when `body` holds at least one ZWNJ/ZWJ (so the carve-out may apply).
 * @param {string} body
 * @returns {boolean}
 */
function hasJoinControl(body) {
  return (
    body.includes(String.fromCodePoint(ZWNJ)) ||
    body.includes(String.fromCodePoint(ZWJ))
  );
}

/**
 * Strip payload-capable invisible chars and report which categories were
 * removed. A single leading U+FEFF (BOM) is preserved as a legitimate marker;
 * interior BOMs and all soft hyphens (U+00AD) are stripped, since either can
 * encode hidden instructions. ZWNJ/ZWJ survive only in a linguistic context
 * (see the carve-out above). `found` names exactly the categories stripped, so
 * a caller never warns about a strip the carve-out skipped.
 * @param {string} text
 * @returns {{ cleaned: string, found: string[] }}
 */
export function stripInvisibleWithReport(text) {
  const hasLeadingBom = text.charCodeAt(0) === 0xfeff;
  const body = hasLeadingBom ? text.slice(1) : text;
  const { cleaned, found } = hasJoinControl(body)
    ? carveStrip(body)
    : bulkStrip(body);
  return { cleaned: hasLeadingBom ? BOM + cleaned : cleaned, found };
}

/**
 * Strip payload-capable invisible chars (cleaned text only). See
 * stripInvisibleWithReport for the BOM and ZWNJ/ZWJ carve-out semantics.
 * @param {string} text
 * @returns {string}
 */
export function stripInvisible(text) {
  return stripInvisibleWithReport(text).cleaned;
}
