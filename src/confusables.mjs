/**
 * Confusable / homoglyph folding for tool-call INPUT fields.
 *
 * Folding look-alike glyphs to their ASCII canon narrows the steganographic
 * channel a model-to-model paste can open and closes the cross-script deny-rule
 * bypass of CVE-2025-54794: a Cyrillic "а" dressed as ASCII "a" would not match
 * an ASCII deny rule, so an attacker could slip a denied path/command past a
 * filter by spelling it in look-alike code points.
 *
 * Folding is per-character and context-free: every glyph the injected scanner
 * flags is replaced with its ASCII (latin) equivalent regardless of its
 * neighbours. This deliberately catches an ISOLATED confusable with no ASCII
 * anchor (a lone Cyrillic "а" in "/а") that a context-SENSITIVE canonicaliser
 * would leave untouched — exactly the bypass to close — while leaving genuine
 * non-confusable non-ASCII (accented Latin, CJK, emoji) alone, since a faithful
 * scanner does not flag those.
 *
 * The confusable scanner is INJECTED, never imported: the canonical engine
 * (namespace-guard's vision-weighted map) is a heavy, separately-owned peer.
 * Pass `{ scan }` where `scan(text)` returns `{ findings: [{ index, char,
 * latinEquivalent }] }` — `index` a UTF-16 offset, `char` the matched glyph
 * (possibly a 2-unit astral char), `latinEquivalent` its ASCII canon.
 */

/**
 * Default path/command fields to fold per tool. Agent-agnostic: the keys are
 * the conventional Claude/Anthropic tool names, but a caller with a different
 * tool surface passes its own `fields` map.
 * @type {Record<string, string[]>}
 */
export const DEFAULT_FIELDS = {
  Bash: ["command"],
  Edit: ["file_path"],
  Write: ["file_path"],
  Read: ["file_path"],
  MultiEdit: ["file_path"],
  NotebookEdit: ["notebook_path"],
};

/**
 * True iff any UTF-16 code unit is outside ASCII (> 0x7F). Surrogates (astral
 * chars) are >= 0xD800 so they count; ASCII control chars (tab, newline) stay
 * ASCII. A plain loop, not a regex, to avoid a control char in the pattern.
 * @param {string} value
 * @returns {boolean}
 */
export function hasNonAscii(value) {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) > 0x7f) return true;
  }
  return false;
}

/**
 * Model-facing note naming the fields whose confusables were folded.
 * @param {string[]} normalized
 * @returns {string}
 */
export function normalizeContext(normalized) {
  return `Confusable characters normalized in: ${normalized.join(", ")}. If a path now fails to resolve, the on-disk name itself contains the look-alike glyph shown.`;
}

// Cap the per-field fold list so a glyph-stuffed input can't bloat the context.
const MAX_REPORTED_FOLDS = 8;

/** @param {Array<{ char: string, latinEquivalent: string }>} findings */
function describeFolds(findings) {
  const folds = [
    ...new Set(
      findings.map(
        (finding) =>
          // char is always a non-empty confusable glyph, so codePointAt(0) is
          // defined; the cast avoids an unreachable `?? 0` fallback branch.
          `U+${
            /** @type {number} */ (finding.char.codePointAt(0))
              .toString(16)
              .toUpperCase()
              .padStart(4, "0")
          } → "${finding.latinEquivalent}"`,
      ),
    ),
  ];
  const shown = folds.slice(0, MAX_REPORTED_FOLDS).join(", ");
  return folds.length > MAX_REPORTED_FOLDS ? `${shown}, …` : shown;
}

/**
 * Replace every scan-flagged confusable with its ASCII (latin) equivalent.
 * `index` is a UTF-16 offset into `text` and `char` is the matched glyph (which
 * may be an astral, 2-unit char); splice highest-index first so a
 * length-changing fold never shifts the offsets of earlier findings.
 * @param {string} text
 * @param {Array<{ index: number, char: string, latinEquivalent: string }>} findings
 * @returns {string}
 */
export function foldConfusables(text, findings) {
  let folded = text;
  for (const finding of [...findings].sort((lhs, rhs) => rhs.index - lhs.index))
    folded =
      folded.slice(0, finding.index) +
      finding.latinEquivalent +
      folded.slice(finding.index + finding.char.length);
  return folded;
}

/**
 * Normalize confusable/homoglyph chars in the path/command fields of a tool
 * call. Returns the updated input plus the fields touched, or null when nothing
 * changed. Throws if the injected scanner fails (the caller fails closed: an
 * un-normalized confusable could slip past a deny rule).
 *
 * `scan` is the injected confusable engine: `scan(text)` → `{ findings }` (an
 * empty `findings` means no confusables). `fields` maps a tool name to the
 * input keys to fold; defaults to {@link DEFAULT_FIELDS}.
 * @param {string} tool
 * @param {any} toolInput
 * @param {{ scan: (text: string) => { findings: Array<{ index: number, char: string, latinEquivalent: string }> }, fields?: Record<string, string[]> }} options
 * @returns {{ updatedInput: any, normalized: string[] } | null}
 */
export function normalizeConfusables(
  tool,
  toolInput,
  { scan, fields = DEFAULT_FIELDS },
) {
  const keys = fields[tool];
  if (!keys || toolInput === null || toolInput === undefined) return null;

  // ASCII fast-path: only a field carrying a non-ASCII code unit can hold a
  // confusable, so all-ASCII input never invokes the (heavy) scanner.
  const candidates = keys.filter(
    (k) => typeof toolInput[k] === "string" && hasNonAscii(toolInput[k]),
  );
  if (candidates.length === 0) return null;

  const normalized = [];
  const updatedInput = { ...toolInput };
  for (const k of candidates) {
    const { findings } = scan(toolInput[k]);
    if (findings.length === 0) continue;
    updatedInput[k] = foldConfusables(toolInput[k], findings);
    normalized.push(`${k} (${describeFolds(findings)})`);
  }

  if (normalized.length === 0) return null;
  return { updatedInput, normalized };
}
