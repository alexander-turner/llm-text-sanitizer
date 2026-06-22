/**
 * Top-level convenience entry for agent-input-sanitizer.
 *
 * `sanitize` always runs the zero-dependency Layer 1 (invisible-char + ANSI
 * stripping, lone-surrogate normalization) and, when `html` is requested,
 * lazy-loads the heavier HTML layer (Layers 2 & 3) so the remark/rehype graph
 * is only paid for by callers that ask for it.
 *
 * The low-level building blocks stay public via the `./invisible` and `./html`
 * subpath entries; import those directly when you want a single layer without
 * the convenience wrapper.
 */
import {
  stripInvisibleWithReport,
  LONG_RUN_RE,
  CATEGORY,
  CATEGORY_LABELS,
} from "./invisible.mjs";

export {
  stripInvisible,
  stripInvisibleWithReport,
  isSgrOnly,
  STRIP,
  SGR_RE,
  CHECKS,
  CATEGORY,
  CATEGORY_LABELS,
  LINGUISTIC_SCRIPTS,
  VS,
  BLANK_NON_CF,
  LONG_RUN_RE,
  LONG_RUN_THRESHOLD,
  SCATTERED_THRESHOLD,
} from "./invisible.mjs";

// Layer 2/3 cheap pre-gates. Re-exported from the dependency-free `./gates.mjs`
// (not `./html.mjs`) so consumers can share the exact HTML-tag/markdown-link
// hints and secret-shape pre-gate without duplicating the regexes — and without
// pulling in the heavy remark/rehype graph that a re-export from `./html.mjs`
// would eagerly load on every root import.
export {
  HTML_TAG_PRESENT,
  MD_LINK_HINT,
  SECRET_HINT,
  SECRET_HINT_EXT,
  matchesSecretHint,
} from "./gates.mjs";

// The two raw control introducers an ANSI sequence can start with: 7-bit
// ESC (U+001B) and the 8-bit C1 CSI (U+009B). Both are category Cc, so the
// invisible-char pass (which targets Cf / variation / blank fillers) never
// removes them; the residual sweep below is what guarantees neither survives.
// eslint-disable-next-line no-control-regex -- matching the raw introducers is the point
const CONTROL_INTRODUCER_RE = /[\u001b\u009b]/g;

// Full ANSI escape grammar (CSI/SGR/OSC-with-BEL), not just SGR: the Layer-1
// guarantee is that no control introducer survives, and a cursor-move or
// erase sequence is as much a display-spoofing hazard as a color one. The
// pattern is linear (every quantified run is bounded or non-overlapping), so it
// carries no catastrophic-backtracking risk on adversarial input.
// prettier-ignore
// eslint-disable-next-line no-control-regex -- matching ESC-led sequences is the point
const ANSI_RE = /[\u001b\u009b][[\]()#;?]*(?:(?:(?:(?:;[-a-zA-Z\d/#&.:=?%@~_]+)*|[a-zA-Z\d]+(?:;[-a-zA-Z\d/#&.:=?%@~_]*)*)?\u0007)|(?:(?:\d{1,4}(?:;\d{0,4})*)?[\dA-PR-TZcf-ntqry=><~]))/g;

// Unpaired UTF-16 surrogates (high not followed by low, or low not preceded by
// high). Normalized before the HTML parser, which throws on a stray byte —
// which would otherwise let a single malformed code unit suppress all output.
const LONE_SURROGATE_RE =
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
function stripAnsiFully(input) {
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
function applyLayer1(text) {
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

/** @param {{ comments: number, hidden: number }} removed */
function describeRemoved(removed) {
  const parts = [];
  if (removed.comments > 0) parts.push(`${removed.comments} HTML comment(s)`);
  if (removed.hidden > 0) parts.push(`${removed.hidden} hidden element(s)`);
  return parts.join(", ");
}

/** @param {{ tags: Record<string, number>, dataSrc: number }} warned */
function describeWarned(warned) {
  const parts = Object.entries(warned.tags).map(
    ([tag, count]) => `${tag}×${count}`,
  );
  if (warned.dataSrc > 0) parts.push(`data: URI×${warned.dataSrc}`);
  return parts.length > 0
    ? `Preserved but reported (page source kept inspectable): ${parts.join(", ")}`
    : "";
}

/**
 * Sanitize untrusted text before any LLM sees it.
 *
 * Always runs Layer 1 (invisible-char + ANSI stripping, lone-surrogate
 * normalization). When `html` is true, also lazy-loads the HTML layer to splice
 * out human-invisible HTML (comments, hidden elements — Layer 2) and detect
 * data-exfil-shaped URLs (Layer 3); the heavy remark/rehype dependency is only
 * imported on that path. The exfil scan runs on the pre-splice text so a beacon
 * URL hidden inside a `display:none` element is still reported, not buried by
 * its own removal.
 *
 * `found` names the categories neutralized; `warnings` carries the
 * operator-facing notices. `cleaned` is always a string, never throws, and
 * changes only carry a warning (no silent suppression).
 * @param {string} text
 * @param {{ html?: boolean }} [options]
 * @returns {Promise<{ cleaned: string, found: string[], warnings: string[] }>}
 */
export async function sanitize(text, { html = false } = {}) {
  /** @type {string[]} */ const found = [];
  /** @type {string[]} */ const warnings = [];

  const { cleaned: layer1, deAnsi, found: invisFound } = applyLayer1(text);
  let cleaned = layer1;
  if (invisFound.length > 0) {
    found.push(...invisFound);
    let msg = `Stripped: ${invisFound.map((code) => CATEGORY_LABELS[code]).join(", ")}`;
    LONG_RUN_RE.lastIndex = 0;
    if (LONG_RUN_RE.test(deAnsi))
      msg += " [LONG RUN — possible injection payload]";
    warnings.push(msg);
  }

  const wellFormed = cleaned.replace(LONE_SURROGATE_RE, "\uFFFD");
  if (wellFormed !== cleaned) {
    cleaned = wellFormed;
    found.push(CATEGORY.LONE_SURROGATES);
    warnings.push("Normalized lone UTF-16 surrogates");
  }

  if (!html) return { cleaned, found, warnings };

  const { sanitizeHtml, detectExfil } = await import("./html.mjs");
  // Scan for exfil URLs on the text BEFORE Layer 2 splices anything out — a
  // beacon URL hidden in a comment or hidden element is more suspicious, not
  // less, yet Layer 2 would otherwise remove it from view before the scan.
  const preSplice = cleaned;

  const layer2 = sanitizeHtml(cleaned);
  if (layer2) {
    if (layer2.text !== cleaned) {
      cleaned = layer2.text;
      if (layer2.removed.comments > 0) found.push(CATEGORY.HTML_COMMENTS);
      if (layer2.removed.hidden > 0) found.push(CATEGORY.HIDDEN_HTML);
      warnings.push(
        `HTML sanitized: ${describeRemoved(layer2.removed)} replaced with placeholders`,
      );
    }
    const preserved = describeWarned(layer2.warned);
    if (preserved) warnings.push(preserved);
  }

  const threats = detectExfil(preSplice);
  if (threats) {
    found.push(CATEGORY.EXFIL_URLS);
    const reasons = [
      ...new Set(
        threats.map(
          (threat) =>
            `${threat.isImage ? "image" : "link"} to ${threat.target}: ${threat.reason}`,
        ),
      ),
    ];
    warnings.push(`Exfil-shaped URLs detected: ${reasons.join("; ")}`);
  }

  return { cleaned, found, warnings };
}
