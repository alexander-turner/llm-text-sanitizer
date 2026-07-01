/**
 * User-prompt verdict: classify a submitted prompt as pass / pass-with-note /
 * block on payload-capable invisible Unicode and ANSI escapes.
 *
 * A prompt pasted from a tampered web page can carry tag characters or
 * zero-width sequences the model reads but the user cannot see, and a
 * prompt-submission channel typically cannot rewrite the prompt in place — so
 * the only way to neutralize a payload is to block. This is the pure decision;
 * a host wraps it in whatever its agent's prompt-submission hook expects.
 *
 * One carve-out: a prompt whose only escape content is SGR color/style codes
 * (`ESC [ params m`) passes with a note instead of blocking. Pasting colored
 * terminal output (test runs, build logs) is the single most common debugging
 * action, and SGR is display-only by the ECMA-48 grammar — it cannot move the
 * cursor, erase the screen, or carry an OSC payload. Anything beyond SGR still
 * blocks, as do the invisible-char thresholds.
 */
import {
  CHECKS,
  CATEGORY,
  CATEGORY_LABELS,
  LONG_RUN_RE,
  LONG_RUN_THRESHOLD,
  SCATTERED_THRESHOLD,
  countPayloadInvisible,
  isSgrOnly,
  SGR_RE,
} from "./invisible.mjs";
import { stripAnsiFully } from "./layer1.mjs";

// The three raw ANSI control introducers a prompt can carry: 7-bit ESC
// (U+001B), 8-bit C1 CSI (U+009B), and 8-bit C1 OSC (U+009D). Gating on ESC
// alone is blind to a pure-C1 sequence whose only escape content is, e.g.,
// `U+009B 2J` (erase) or `U+009D 0;...BEL` (OSC): Layer 1 strips it, dropping
// the invisible count to zero, so the prompt reads clean. Layer 1's CSI/OSC
// branches recognize all three, so this gate must too. C1 ST (U+009C) is a
// terminator, never an introducer, so it is deliberately absent.
// eslint-disable-next-line no-control-regex -- the raw introducers are exactly what we detect
const ANSI_INTRODUCER = /[]/;

/**
 * True when every ANSI introducer in `prompt` belongs to a display-only SGR
 * color sequence -- the note carve-out's precondition. `isSgrOnly` covers the
 * 7-bit ESC and C1 CSI introducers but is blind to the C1 OSC introducer
 * (U+009D), so a `U+009D 0;title BEL` prompt slips its check and is mis-read as
 * SGR-only; re-test the SGR-stripped prompt against the full introducer set so
 * a residual C1-OSC (or any non-SGR escape) denies the note and falls through
 * to block.
 * @param {string} prompt
 * @returns {boolean}
 */
function isSgrColorOnly(prompt) {
  return isSgrOnly(prompt) && !ANSI_INTRODUCER.test(prompt.replace(SGR_RE, ""));
}

/**
 * Human-facing block reason: what was detected, the thresholds, a code-point
 * sample of the long run (if any), and how to recover.
 * @param {string[]} categories
 * @param {number} invisibleCount
 * @param {string | null} longRunSample
 * @returns {string}
 */
export function formatReason(categories, invisibleCount, longRunSample) {
  const parts = [
    `Detected: ${categories.join(", ")}.`,
    `Invisible char count: ${invisibleCount} (long-run threshold: ${LONG_RUN_THRESHOLD}, scattered threshold: ${SCATTERED_THRESHOLD}).`,
  ];
  if (longRunSample) {
    const cps = [...longRunSample]
      .slice(0, 16)
      .map(
        (ch) =>
          "U+" +
          /** @type {number} */ (ch.codePointAt(0))
            .toString(16)
            .toUpperCase()
            .padStart(4, "0"),
      )
      .join(" ");
    parts.push(`Long-run sample (first 16 code points): ${cps}.`);
  }
  parts.push(
    "Resubmit the prompt with invisible/ANSI characters removed. If you pasted this from a webpage, the source may be carrying a prompt-injection payload.",
  );
  return parts.join(" ");
}

/**
 * Pure verdict for a user prompt: pass through, pass with an SGR note, or
 * block. `strip` (the ANSI stripper, defaulting to the package's
 * {@link stripAnsiFully}) runs on every prompt so invisibles smuggled *inside*
 * an ANSI sequence (an OSC string) are stripped before the invisible-char
 * thresholds are counted; it is injectable so a host can substitute its own
 * stripper or exercise the fail-closed path.
 * @param {string} prompt
 * @param {(s: string) => string} [strip]
 * @returns {{action:"pass"} | {action:"note"} | {action:"block", reason:string}}
 */
export function classifyPrompt(prompt, strip = stripAnsiFully) {
  if (!prompt) return { action: "pass" };

  const hasAnsi = ANSI_INTRODUCER.test(prompt);
  const deAnsi = strip(prompt);

  const longRunSample = deAnsi.match(LONG_RUN_RE)?.[0] ?? null;
  // Count only PAYLOAD invisibles for the scatter gate: ZWNJ/ZWJ (and emoji
  // VS16) that do real rendering work are excluded, so a legitimately
  // joiner-dense multilingual prompt (formal Persian, an emoji ZWJ sequence) is
  // not blocked by sheer joiner count. This mirrors carveStrip's own
  // payloadInvis < SCATTERED_THRESHOLD gate so the block and strip layers agree.
  const invisibleCount = countPayloadInvisible(deAnsi);
  const invisiblesBelowThreshold =
    longRunSample === null && invisibleCount < SCATTERED_THRESHOLD;

  if (!hasAnsi && invisiblesBelowThreshold) return { action: "pass" };

  // Display-only color codes in an otherwise clean prompt: pass with a note
  // instead of blocking, so pasted colored logs remain usable.
  if (hasAnsi && invisiblesBelowThreshold && isSgrColorOnly(prompt))
    return { action: "note" };

  // CHECKS pairs a machine-readable category code with its detector; map each
  // matched code to its human label for the user-facing block reason.
  const categories = CHECKS.filter(([, re]) => deAnsi.search(re) !== -1).map(
    ([code]) => CATEGORY_LABELS[code],
  );
  if (hasAnsi) categories.push(CATEGORY_LABELS[CATEGORY.ANSI]);
  return {
    action: "block",
    reason: formatReason(categories, invisibleCount, longRunSample),
  };
}
