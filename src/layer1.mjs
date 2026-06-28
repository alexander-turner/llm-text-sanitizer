/**
 * Layer 1: ANSI + invisible-character stripping with lone-surrogate
 * normalization. The zero-dependency core shared by the convenience `sanitize`
 * (index.mjs), the tool-output pipeline (output.mjs), and the Edit-repair
 * rehydrator (rehydrate.mjs) — a single implementation so every consumer
 * derives the EXACT view the model was shown (a re-implementation would drift,
 * and rehydration's soundness gate depends on re-cleaning reproducing the view).
 */
import { stripInvisibleWithReport, CATEGORY } from "./invisible.mjs";

// The two raw control introducers an ANSI sequence can start with: 7-bit
// ESC (U+001B) and the 8-bit C1 CSI (U+009B). Both are category Cc, so the
// invisible-char pass (which targets Cf / variation / blank fillers) never
// removes them; the residual sweep below is what guarantees neither survives.
// eslint-disable-next-line no-control-regex -- matching the raw introducers is the point
const CONTROL_INTRODUCER_RE = /[\u001b\u009b]/g;

// An OSC (Operating System Command) string is `<introducer> … <terminator>`.
// Introducer: 7-bit `ESC]` or 8-bit C1 OSC (U+009D). Terminator: ST (`ESC\` or
// 8-bit C1 ST U+009C) OR the legacy BEL (U+0007). The body is everything up to
// the terminator — a title, a clickable-hyperlink URL, a clipboard write — i.e.
// attacker-controlled PAYLOAD TEXT. Matching the introducer alone (leaving the
// body) would let that payload survive into the model's view, so the OSC branch
// consumes the introducer, the whole body, AND the terminator as one unit.
//
// Two alternatives, tried in order: (1) a properly TERMINATED string — a body
// of bytes that no terminator can start with (the negated class makes that run
// unambiguous and backtrack-free), then a terminator; (2) anything else from
// the introducer to END-OF-STRING (`[\s\S]*$`). Alternative 2 is the fail-closed
// catch-all: an UNTERMINATED introducer, or one whose only "terminator" is an
// interior bare ESC (which is not a valid ST), drops the entire dangling
// remainder rather than leaving the C1-OSC introducer (U+009D) and its payload
// behind for the next pass to mis-handle (that residue broke idempotence). Both
// alternatives are linear, so the branch stays linear.
const OSC_INTRO = "(?:\\u001b\\]|\\u009d)";
const OSC_TERM = "(?:\\u001b\\\\|\\u009c|\\u0007)";
const OSC_BRANCH = `${OSC_INTRO}(?:[^\\u0007\\u001b\\u009c\\u009d]*${OSC_TERM}|[\\s\\S]*$)`;

// CSI / two-byte ESC sequences (cursor moves, erase, SGR color, charset/DEC
// selectors): an introducer, a bounded private-intro run, optional numeric
// params, and a single final byte. Not an enforcement boundary on its own — any
// introducer this declines to match is still removed by the residual sweep in
// applyLayer1 — but matching the whole sequence keeps the common case one clean
// deletion (and avoids a lone-ESC residual on every styled line).
//
// The private-intro class is BOUNDED ({0,12}, not *) on purpose: ; and # live
// in both this class and the parameter group that follows, so an unbounded *
// here lets a ;#;#... run be split between the two quantifiers — O(n^2)
// backtracking on an ESC;#;#... string that never completes a sequence
// (CodeQL js/polynomial-redos). A constant bound makes the intro a constant
// factor, so the whole match is linear; a real sequence never carries more than
// a couple of intro bytes.
const CSI_BRANCH =
  "[\\u001b\\u009b][[()#;?]{0,12}(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~])";

// Full ANSI escape grammar (OSC first so `ESC]` / C1-OSC is consumed as a whole
// string, not split by the CSI branch), not just SGR: the Layer-1 guarantee is
// that no control introducer and no OSC payload survives, and a cursor-move or
// erase sequence is as much a display-spoofing hazard as a color one. Built from
// `\uXXXX`-escaped string parts via `new RegExp`, so no raw control byte sits in
// the source (no no-control-regex disable needed).
const ANSI_RE = new RegExp(`(?:${OSC_BRANCH}|${CSI_BRANCH})`, "gu");

// Unpaired UTF-16 surrogates (high not followed by low, or low not preceded by
// high). Normalized before any HTML parser, which throws on a stray byte —
// which would otherwise let a single malformed code unit suppress all output.
export const LONE_SURROGATE_RE =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/**
 * Strip ANSI escape sequences to a fixed point. Removing one sequence can
 * reconstitute another around it (a lone ESC left of `ESC[32m[0m` gains the
 * trailing `[0m` once the inner sequence is removed, forming a brand-new valid
 * sequence the single pass would miss), so iterate until stable: every changed
 * pass consumes at least one ESC introducer, so the pass count is bounded by
 * the input's ESC count, and ANSI-free text exits after one pass.
 * @param {string} input
 * @returns {string}
 */
export function stripAnsiFully(input) {
  let prev = input;
  let out = prev.replace(ANSI_RE, "");
  while (out !== prev) {
    prev = out;
    out = prev.replace(ANSI_RE, "");
  }
  return out;
}

/**
 * Layer 1: ANSI + invisible-char strip with a result guaranteed free of every
 * raw ANSI control introducer (7-bit ESC U+001B and 8-bit C1 CSI U+009B).
 *
 * Removing an invisible character can reconstitute an escape its split hid from
 * the ANSI pass (`ESC`<ZWSP>`[32m` → `ESC[32m`), so strip ANSI again after the
 * invisible pass — but only when stripInvisible changed something, since
 * reconstitution is impossible otherwise and the re-strip is a wasted pass on
 * the hot clean path. The ANSI strip still cannot match an *incomplete*
 * reconstituted sequence (a lone `ESC[` left when an inner complete sequence is
 * removed from a nested split), so a final sweep removes every residual raw
 * introducer outright — that sweep, not the regex matching, is the guarantee
 * that no control introducer survives. `deAnsi` is the ANSI strip of the
 * original (invisible runs intact), the scope a LONG_RUN payload check needs.
 * @param {string} text
 * @returns {{ cleaned: string, deAnsi: string, found: string[] }}
 */
export function applyLayer1(text) {
  const deAnsi = stripAnsiFully(text);
  // stripInvisibleWithReport returns `found` for exactly the categories it
  // removed — so a ZWNJ/ZWJ the carve-out PRESERVES never registers as a strip,
  // and the leading-BOM exception is already handled inside it.
  const { cleaned: afterInvis, found } = stripInvisibleWithReport(deAnsi);
  let ansiFound = deAnsi.length !== text.length;

  let cleaned = afterInvis;
  if (afterInvis !== deAnsi) {
    const reStripped = stripAnsiFully(afterInvis);
    if (reStripped.length !== afterInvis.length) ansiFound = true;
    cleaned = reStripped;
  }
  const swept = cleaned.replace(CONTROL_INTRODUCER_RE, "");
  if (swept !== cleaned) {
    cleaned = swept;
    ansiFound = true;
  }

  if (ansiFound) found.push(CATEGORY.ANSI);
  return { cleaned, deAnsi, found };
}
