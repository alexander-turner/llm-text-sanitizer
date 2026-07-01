/**
 * Invisible-character + ANSI/SGR primitives with no external runtime deps.
 *
 * Removes payload-capable Unicode (general-category Cf format chars, variation
 * selectors, blank-rendering fillers, soft hyphens, interior BOMs) while
 * preserving ZWNJ/ZWJ in genuine linguistic and emoji contexts, and reports
 * which categories were removed. The linguistic carve-out is driven by the
 * generated Unicode Joining_Type / virama tables in ./joining-type.mjs (a
 * sibling data module, not a package), so it decides preservation from the
 * actual cursive-join semantics rather than a hand-rolled script guess.
 */
import { joiningType, isVirama } from "./joining-type.mjs";

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
// legitimate non-English output. Preserve them only where they do real
// rendering work, decided SYNTACTICALLY from the neighbours' Unicode
// Joining_Type (see isPreservedJoiner): a joiner between two cursive letters, an
// Indic joiner after a virama, an emoji joiner between emoji components. Strip
// them as payload everywhere else — leading/trailing, next to a non-joining
// character (ASCII, punctuation, a non-connecting letter), or inside a joiner
// run. Over-strip beats under-strip only on genuine ambiguity; a joiner sitting
// between two real cursive letters is treated as content and kept.
const ZWNJ = 0x200c;
const ZWJ = 0x200d;

// Max joiners the carve-out will PRESERVE within one uninterrupted joined
// cluster (a `letter (joiner letter)*` chain, or an emoji ZWJ sequence). A real
// word or emoji glyph needs only a handful in a row — the longest standard emoji
// ZWJ sequences (family-of-four, profession+ZWJ) carry three; a Persian
// compound a couple. Past this many consecutive PRESERVED joiners with no real
// gap between them, the chain is treated as a zero-width payload channel (an
// attacker alternates `letter joiner letter joiner …` so every joiner still sits
// between two cursive letters) and the surplus joiners are stripped. The counter
// resets at any genuine gap — two visible characters in a row, i.e. text that is
// NOT part of a joined cluster — so an ordinary single joiner per word is kept.
export const CONSECUTIVE_JOINER_CAP = 8;

// Floor on the document-wide preserve budget. The Joining_Type gate strips
// joiners that do no rendering work regardless of count, so the bulk covert
// channel (ZWNJ scattered through Latin/ASCII/mixed text) is closed by shape,
// not by counting. What remains is the residual channel of MEANINGFUL joiners
// stuffed into genuine cursive/Indic cover text — each individually legitimate,
// so indistinguishable one at a time. THIS budget (with CONSECUTIVE_JOINER_CAP
// and SCATTERED_THRESHOLD) is the explicit, tunable bound on that residual
// channel; it is not derived, and tightening it trades covert-channel width for
// clipping genuinely dense prose. The allowance is proportional to visible
// length (PRESERVED_JOINER_PER_VISIBLE), never below this floor; the floor keeps
// short but joiner-dense strings (a lone emoji ZWJ sequence, a two-word Persian
// phrase) un-flagged. Past the allowance the surplus is stripped AND reported.
export const TOTAL_PRESERVED_JOINER_BUDGET = 16;

// Visible code points required per additional preserved joiner above the floor.
// Measured formal/literary Persian runs ~1 ZWNJ per 5 words (~25 visible chars);
// 1-per-8 sits comfortably above real prose density while still bounding the
// residual channel to a fixed fraction of the cover text.
export const PRESERVED_JOINER_PER_VISIBLE = 8;

// Scripts whose orthography uses ZWNJ/ZWJ between letters as a rendering
// control. The runtime gate is now script-agnostic (it reads Joining_Type, so it
// covers every cursive/Brahmic script, not just these), but this list remains
// the public, TESTED SSOT of the scripts the carve-out is designed for: the
// suite drives one preserve-case per entry, so a regression in any of them
// fails.
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

/** A cursive-joining letter: Joining_Type dual, right, or left. (C is a join
 * control, T is a transparent mark, U is non-joining — none is a letter that a
 * ZWNJ/ZWJ does rendering work between.)
 * @param {string} jt @returns {boolean} */
const isCursiveLetter = (jt) => jt === "D" || jt === "R" || jt === "L";

/** The Joining_Type of a single-code-point string, or "U" for "" (boundary).
 * @param {string} ch @returns {string} */
const jtOf = (ch) => (ch ? joiningType(ch.codePointAt(0) ?? -1) : "U");

/** True when `ch` is itself a ZWNJ/ZWJ (used to reject joiner runs).
 * @param {string} ch @returns {boolean} */
function isJoinControl(ch) {
  const cp = ch ? ch.codePointAt(0) : -1;
  return cp === ZWNJ || cp === ZWJ;
}

/**
 * The nearest neighbour of index `i` in direction `dir`, skipping Transparent
 * (combining-mark) code points, as the Unicode cursive-joining algorithm does —
 * a harakat between a letter and a ZWNJ does not break the join. Returns "" past
 * the string boundary.
 * @param {string[]} cps @param {number} i @param {number} dir  -1 or +1
 * @returns {string}
 */
function effectiveNeighbor(cps, i, dir) {
  for (let j = i + dir; j >= 0 && j < cps.length; j += dir) {
    if (jtOf(cps[j]) !== "T") return cps[j];
  }
  return "";
}

/**
 * True when the joiner at `cps[i]` does real rendering work and so must be
 * preserved rather than stripped, decided from the neighbours' Joining_Type:
 *   - emoji ZWJ: between two emoji components (its left pictograph may sit behind
 *     a VS16, so step over selectors — see leftNonSelector);
 *   - Indic joiner: immediately after a virama;
 *   - Arabic-family joiner: between two cursive letters (ZWNJ needs both, ZWJ at
 *     least one — it forces a connected form). A joiner whose effective neighbour
 *     is ANOTHER joiner is a run (a zero-width payload channel) and is rejected.
 * Leading/trailing joiners fall out because "" has Joining_Type U.
 * @param {string[]} cps @param {number} i
 * @returns {boolean}
 */
function isPreservedJoiner(cps, i) {
  const cp = cps[i].codePointAt(0) ?? -1;
  if (cp !== ZWNJ && cp !== ZWJ) return false;
  const prev = cps[i - 1] ?? "";
  const next = cps[i + 1] ?? "";
  // Emoji ZWJ sequences use ZWJ only; the real left neighbour is the pictograph.
  if (
    cp === ZWJ &&
    EMOJI_LEFT.test(leftNonSelector(cps, i)) &&
    EMOJI_BASE.test(next)
  )
    return true;
  // Indic: meaningful only immediately after a virama (halant / half-form).
  if (prev && isVirama(prev.codePointAt(0) ?? -1)) return true;
  // Arabic-family cursive joining, on the nearest non-Transparent neighbours.
  const left = effectiveNeighbor(cps, i, -1);
  const right = effectiveNeighbor(cps, i, 1);
  if (isJoinControl(left) || isJoinControl(right)) return false; // joiner run
  const lc = isCursiveLetter(jtOf(left));
  const rc = isCursiveLetter(jtOf(right));
  return cp === ZWNJ ? lc && rc : lc || rc;
}

/**
 * True when `cps[i]` is an emoji presentation selector (U+FE0F) directly after a
 * pictograph/skin-tone modifier — part of a visible emoji, not a hidden VS run,
 * so it is preserved (a longer selector run still surfaces: the next selector's
 * left neighbour is itself a selector, not a pictograph).
 * @param {string[]} cps @param {number} i
 * @returns {boolean}
 */
function isEmojiPresentationSelector(cps, i) {
  return (
    cps[i].codePointAt(0) === EMOJI_PRESENTATION_SELECTOR &&
    EMOJI_LEFT.test(cps[i - 1] ?? "")
  );
}

/**
 * Per-invisible carve-out analysis, shared by carveStrip and
 * countPayloadInvisible: for each code point, its CHECKS category (null when
 * visible) and its preserve `kind` ("joiner" | "emojivs" | null). Everything
 * invisible that is NOT preserve-eligible is payload; the scatter floor counts
 * only that, so meaningful joiners never push honest prose over the threshold.
 * @param {string[]} cps
 * @returns {{ codes: (string|null)[], kind: (string|null)[], payloadInvis: number, visibleLen: number }}
 */
function analyzeCarve(cps) {
  const codes = cps.map(classify);
  const kind = cps.map((_, i) => {
    if (codes[i] === null) return null;
    if (isPreservedJoiner(cps, i)) return "joiner";
    if (isEmojiPresentationSelector(cps, i)) return "emojivs";
    return null;
  });
  let payloadInvis = 0;
  let visibleLen = 0;
  for (let i = 0; i < cps.length; i++) {
    if (codes[i] === null) visibleLen++;
    else if (kind[i] === null) payloadInvis++;
  }
  return { codes, kind, payloadInvis, visibleLen };
}

/**
 * Count the PAYLOAD invisible code points in `text`: those the carve-out would
 * strip, excluding ZWNJ/ZWJ (and emoji VS16) that do real rendering work.
 * Consumers that gate on invisible density (e.g. the prompt classifier's scatter
 * threshold) use this so legitimate dense multilingual prose is not mistaken for
 * a hidden channel.
 * @param {string} text
 * @returns {number}
 */
export function countPayloadInvisible(text) {
  return analyzeCarve(Array.from(text)).payloadInvis;
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
  const cps = Array.from(body);
  // Pass 1: classify + evaluate the gate once (see analyzeCarve). Only PAYLOAD
  // invisibles count toward the scatter floor, so a meaningful-joiner-dense text
  // (formal Persian, a long Devanagari conjunct run) stays under it.
  const { codes, kind, payloadInvis, visibleLen } = analyzeCarve(cps);
  // SCATTERED_THRESHOLD is the floor on payload invisibles: past it the document
  // is drowning in hidden bytes, so the carve-out is off and even a meaningful
  // joiner is stripped (threshold-evasion catch — over-strip beats under).
  const allowCarveOut = payloadInvis < SCATTERED_THRESHOLD;
  // Document-wide preserve allowance, proportional to visible text but never
  // below the floor (see TOTAL_PRESERVED_JOINER_BUDGET / PRESERVED_JOINER_PER_VISIBLE).
  const maxPreserved = Math.max(
    TOTAL_PRESERVED_JOINER_BUDGET,
    Math.ceil(visibleLen / PRESERVED_JOINER_PER_VISIBLE),
  );

  const foundCodes = new Set();
  let out = "";
  // Preserved JOINERS in the current uninterrupted cluster (emoji presentation
  // selectors don't chain, so they are exempt). A genuine gap (two visible chars
  // in a row — see prevVisible) resets it; past the cap the surplus is stripped.
  let joinerRun = 0;
  // Preserved joiners/selectors across the WHOLE string — never reset at a gap,
  // so it bounds the document-wide channel joinerRun cannot. Past maxPreserved a
  // joiner is stripped and its category reported.
  let preservedTotal = 0;
  let prevVisible = false;
  for (let i = 0; i < cps.length; i++) {
    const code = codes[i];
    if (code === null) {
      // A visible char following another visible char is a real word/segment
      // boundary, not a join — the joined cluster (if any) ended here.
      if (prevVisible) joinerRun = 0;
      prevVisible = true;
      out += cps[i]; // ordinary visible character
      continue;
    }
    const joiner = kind[i] === "joiner";
    if (
      allowCarveOut &&
      kind[i] !== null &&
      preservedTotal < maxPreserved &&
      (!joiner || joinerRun < CONSECUTIVE_JOINER_CAP)
    ) {
      if (joiner) joinerRun++;
      preservedTotal++;
      prevVisible = false; // a joiner/selector keeps the cluster open
      out += cps[i];
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
