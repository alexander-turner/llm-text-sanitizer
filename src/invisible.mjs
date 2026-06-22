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

// Code points that render blank / zero-width but are NOT general category Cf,
// so the \p{Cf} check below misses them: the Hangul fillers (category Lo,
// U+115F/U+1160/U+3164/U+FFA0) and the Braille blank pattern (category So,
// U+2800). A run of these carries a hidden payload exactly as zero-widths do.
export const BLANK_NON_CF = "\u115F\u1160\u3164\uFFA0\u2800";

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
  [CATEGORY.BLANK_FILLERS, new RegExp(`[${BLANK_NON_CF}]`, REGEX_FLAGS)],
];

export const STRIP = new RegExp(
  CHECKS.map(([, regex]) => regex.source).join("|"),
  REGEX_FLAGS,
);

// SGR (Select Graphic Rendition): ESC [ <digits/semicolons> m — colors, bold,
// reset. The grammar is closed: params are [0-9;]* and the final byte is `m`,
// so a match can only restyle text, never reposition the cursor, erase, or
// smuggle an OSC string. Text is "SGR-only" when removing these leaves no ESC
// byte at all — a lone or partial escape therefore is not SGR-only.
// eslint-disable-next-line no-control-regex -- matching ESC-led sequences is the point
export const SGR_RE = /\x1b\[[0-9;]*m/g;

// eslint-disable-next-line no-control-regex -- ESC (U+001B) is exactly what we test for
const ESC_RE = /\x1b/;

/**
 * True when every ESC byte in `text` belongs to a display-only SGR color
 * sequence (so stripping the ANSI removed only cosmetic styling, nothing that
 * could move the cursor, erase, or carry a payload).
 * @param {string} text
 * @returns {boolean}
 */
export function isSgrOnly(text) {
  return !ESC_RE.test(text.replace(SGR_RE, ""));
}

export const LONG_RUN_THRESHOLD = 10;

/** Total invisible-char count above which a file/prompt is treated as
 * payload-capable even without a long run (threshold-evasion catch). */
export const SCATTERED_THRESHOLD = 30;

export const LONG_RUN_RE = new RegExp(
  `(?:${STRIP.source}){${LONG_RUN_THRESHOLD},}`,
  REGEX_FLAGS,
);

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
 * Carve-out strip (a ZWNJ/ZWJ is present): walk code points, preserving a join
 * control only where isPreservedJoiner holds AND the text stays under the
 * scatter floor — otherwise it is stripped like any other payload byte. `found`
 * reports only categories actually removed, so a preserved joiner never makes
 * the caller claim a strip that did not happen.
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
  for (let i = 0; i < cps.length; i++) {
    const ch = cps[i];
    const code = classify(ch);
    if (code === null) {
      out += ch; // ordinary visible character
      continue;
    }
    if (
      allowCarveOut &&
      isPreservedJoiner(ch, cps[i - 1] ?? "", cps[i + 1] ?? "")
    ) {
      out += ch;
      continue;
    }
    foundCodes.add(code);
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
