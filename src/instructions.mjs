/**
 * Instruction-file scanner + auto-cleaner for hidden-Unicode injection.
 *
 * Agent instruction files (CLAUDE.md / AGENTS.md / SKILL.md / any `.claude`
 * markdown) load directly as model context, bypassing a tool-output sanitizer,
 * so invisible Unicode pasted into them reaches the model raw — invisible in an
 * editor but read as instructions. This module finds runs of payload-capable
 * invisible characters, decodes the common encodings (Unicode-tag → ASCII,
 * zero-width binary), catches scattered threshold-evasion payloads, and (via
 * {@link cleanFile}) strips them.
 *
 * The target file set is CALLER-SUPPLIED: pass the globs your agent's
 * instruction files live under (e.g. `["CLAUDE.md", "AGENTS.md",
 * ".claude/**\/*.md", "**\/SKILL.md"]`), so no agent's convention is baked in.
 */
import { readFileSync, globSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import {
  LONG_RUN_RE,
  STRIP,
  SCATTERED_THRESHOLD,
  stripInvisible,
} from "./invisible.mjs";

/**
 * Decode a run of invisible characters to its likely payload. Recognizes the
 * two common smuggling encodings — Unicode tag characters (U+E0001–U+E007F map
 * directly to ASCII) and zero-width binary (ZWSP=0, ZWNJ=1, ZWJ=separator) —
 * and otherwise reports the raw code points.
 * @param {string} run
 * @returns {{ method: string, decoded: string }}
 */
export function decodeRun(run) {
  const cps = [...run].map((ch) => /** @type {number} */ (ch.codePointAt(0)));

  // Tag characters U+E0001-U+E007F map directly to ASCII
  const tagAscii = cps
    .filter((cp) => cp >= 0xe0001 && cp <= 0xe007f)
    .map((cp) => String.fromCharCode(cp - 0xe0000))
    .join("");

  if (tagAscii.length > 0) {
    return { method: "Unicode tag characters → ASCII", decoded: tagAscii };
  }

  // Zero-width binary encoding: ZWSP=0, ZWNJ=1, ZWJ=group separator.
  const ZW_BIT = new Map([
    [0x200b, "0"],
    [0x200c, "1"],
    [0x200d, "|"],
  ]);
  if (cps.every((cp) => ZW_BIT.has(cp))) {
    const bits = cps.map((cp) => ZW_BIT.get(cp)).join("");
    return {
      method: "zero-width binary encoding",
      decoded: `[${cps.length} zero-width chars: ${bits.slice(0, 80)}]`,
    };
  }

  // Mixed/unknown
  return {
    method: "invisible Unicode sequence",
    decoded: cps
      .map((cp) => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`)
      .join(" "),
  };
}

/**
 * Scan a file's text for hidden-Unicode injection. Reports each long invisible
 * run (with its decoded payload) plus a single scattered-chars finding when the
 * non-run invisible count crosses the threshold-evasion floor.
 * @param {string} content
 * @returns {Array<{ line: number, charCount: number, method: string, decoded: string }>}
 */
export function scanText(content) {
  const findings = [];
  LONG_RUN_RE.lastIndex = 0;
  let match;
  let runChars = 0;
  while ((match = LONG_RUN_RE.exec(content)) !== null) {
    const lineNum = content.slice(0, match.index).split("\n").length;
    const charCount = [...match[0]].length;
    runChars += charCount;
    findings.push({ line: lineNum, charCount, ...decodeRun(match[0]) });
  }

  // Threshold-evasion: scattered invisible chars not in a long run can still be
  // a payload. Always evaluated; chars already in a run are excluded so they
  // aren't double-counted.
  const allInvisible = content.match(STRIP);
  const scattered = (allInvisible ? allInvisible.length : 0) - runChars;
  if (scattered >= SCATTERED_THRESHOLD) {
    findings.push({
      line: 0,
      charCount: scattered,
      method: "scattered invisible chars (possible threshold evasion)",
      decoded: `[${scattered} invisible chars distributed across file]`,
    });
  }

  return findings;
}

/**
 * Expand `globs` (relative to `cwd`) to absolute file paths, skipping
 * `node_modules`. The glob set is the caller's instruction-file convention.
 * @param {string[]} globs
 * @param {{ cwd?: string }} [options]
 * @returns {string[]}
 */
export function findInstructionFiles(globs, { cwd = process.cwd() } = {}) {
  const seen = new Set();
  for (const pattern of globs)
    for (const name of globSync(pattern, {
      cwd,
      exclude: (entry) => entry === "node_modules",
    }))
      seen.add(join(cwd, name));
  return [...seen];
}

/**
 * Scan every instruction file matched by `globs` and return only those with
 * findings, each path reported relative to `cwd`. Unreadable/missing files are
 * skipped. Pure scan — no mutation; pair with {@link cleanFile} to strip.
 * @param {string[]} globs
 * @param {{ cwd?: string }} [options]
 * @returns {Array<{ file: string, findings: ReturnType<typeof scanText> }>}
 */
export function scanInstructionFiles(globs, { cwd = process.cwd() } = {}) {
  const out = [];
  for (const file of findInstructionFiles(globs, { cwd })) {
    let content;
    try {
      content = readFileSync(file, "utf-8");
    } catch {
      continue; // missing or unreadable
    }
    const findings = scanText(content);
    if (findings.length > 0) out.push({ file: relative(cwd, file), findings });
  }
  return out;
}

/**
 * Strip payload-capable invisible characters from `absPath` in place. Returns
 * true when the file changed (it held a payload), false when it was already
 * clean. Throws if the file cannot be read or written (the caller decides
 * whether an unwritable contaminated file is fatal or falls back to alerting).
 * @param {string} absPath
 * @returns {boolean}
 */
export function cleanFile(absPath) {
  const original = readFileSync(absPath, "utf-8");
  const stripped = stripInvisible(original);
  if (stripped === original) return false;
  writeFileSync(absPath, stripped);
  return true;
}
