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
import {
  readFileSync,
  globSync,
  writeFileSync,
  renameSync,
  lstatSync,
  realpathSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { join, relative, resolve, isAbsolute, dirname, sep } from "node:path";
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

  // Zero-width binary encoding: ZWSP=0, ZWNJ=1, ZWJ=group separator.
  const ZW_BIT = new Map([
    [0x200b, "0"],
    [0x200c, "1"],
    [0x200d, "|"],
  ]);

  if (tagAscii.length > 0) {
    // A run can carry BOTH tag-ASCII and zero-width chars; the strip removes the
    // whole run regardless, but the operator-facing `decoded` must reflect the
    // zero-width portion too rather than silently dropping it.
    const zwCount = cps.filter((cp) => ZW_BIT.has(cp)).length;
    const note = zwCount > 0 ? ` + ${zwCount} zero-width char(s)` : "";
    return {
      method: "Unicode tag characters → ASCII",
      decoded: `${tagAscii}${note}`,
    };
  }

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
 * True when `realChild` is `realRoot` itself or lives beneath it. Both inputs
 * must already be realpath-resolved absolute paths. Containment is tested with
 * `relative(root, child)`: the result is "" when they are the same path, and
 * for a true descendant it is a forward path with no `..` segment and is not
 * itself absolute — so a sibling like `/proj-evil` (relative => `../proj-evil`)
 * is correctly rejected.
 * @param {string} realRoot
 * @param {string} realChild
 * @returns {boolean}
 */
function isContained(realRoot, realChild) {
  const rel = relative(realRoot, realChild);
  return (
    rel === "" ||
    (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel))
  );
}

/**
 * Classify a glob match for containment: resolve it to a real (symlink-
 * followed) path and decide whether to keep, drop, or reject it. Two failure
 * modes are kept distinct:
 *
 *   - The realpath ESCAPES `realRoot` → THROW. A scanner pointed outside its
 *     own tree is a caller misconfiguration that must surface loudly, not a
 *     file silently skipped while the caller believes it was scanned.
 *   - The path cannot be resolved at all (ENOENT/EACCES — a dangling symlink or
 *     unreadable entry that still lives inside the tree) → return false to SKIP
 *     it, matching scanInstructionFiles' existing skip-on-unreadable behavior.
 *     A stale symlink in a project must not abort scanning every other file.
 *
 * A genuine resolution failure is never allowed to masquerade as a
 * containment pass: an unresolvable path is skipped, only a successfully
 * resolved in-tree path returns true.
 * @param {string} absPath  absolute path to a glob match
 * @param {string} realRoot  realpath of the scan root
 * @param {string} pattern  the glob that produced this match
 * @returns {boolean} true to keep the match, false to skip an unresolvable one
 */
function keepContained(absPath, realRoot, pattern) {
  let real;
  try {
    real = realpathSync(absPath);
  } catch {
    return false; // dangling/unreadable in-cwd match: skip, do not abort
  }
  if (isContained(realRoot, real)) return true;
  throw new Error(
    `instruction-file path escapes scan root: pattern ${JSON.stringify(
      pattern,
    )} matched ${JSON.stringify(absPath)} which resolves to ${JSON.stringify(
      real,
    )} outside ${JSON.stringify(realRoot)}`,
  );
}

/**
 * Expand `globs` (relative to `cwd`) to absolute file paths, skipping
 * `node_modules`. The glob set is the caller's instruction-file convention.
 *
 * Containment is enforced per match (see {@link keepContained}): a match whose
 * realpath escapes `cwd` — via `..`, an absolute-path glob, or a symlink
 * pointing outside — THROWS, since reaching outside the tree is a caller
 * misconfiguration. A match that simply cannot be resolved (a dangling symlink
 * or unreadable entry inside the tree) is SKIPPED, so one stale symlink never
 * aborts scanning the rest of the project.
 * @param {string[]} globs
 * @param {{ cwd?: string }} [options]
 * @returns {string[]}
 */
export function findInstructionFiles(globs, { cwd = process.cwd() } = {}) {
  const realRoot = realpathSync(resolve(cwd));
  const seen = new Set();
  for (const pattern of globs)
    for (const name of globSync(pattern, {
      cwd,
      exclude: (entry) => entry === "node_modules",
    })) {
      // globSync returns absolute paths verbatim for an absolute pattern and
      // cwd-relative names otherwise; joining an already-absolute name would
      // double the prefix into a nonexistent path (the absolute-glob miss bug).
      const absPath = isAbsolute(name) ? name : join(cwd, name);
      if (keepContained(absPath, realRoot, pattern)) seen.add(absPath);
    }
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
 * Atomically replace `absPath`'s contents with `data`, preserving `mode`.
 *
 * Writes to a sibling temp in the same directory, then `rename`s it over the
 * original (same dir => same filesystem => the rename is atomic, not a
 * cross-device copy). The temp name is UNPREDICTABLE (`tmpName()` defaults to
 * crypto-random) and the temp is created with the exclusive flag "wx"
 * (O_CREAT|O_EXCL): if the path already exists — including an attacker-planted
 * symlink at a guessable temp name — the open fails (EEXIST) and does NOT follow
 * the link to clobber its target. On the rare collision we fail loud rather than
 * retry into a different attacker-controlled path. `tmpName` is injectable for
 * tests to force a known temp path; production callers never pass it.
 * @param {string} absPath
 * @param {string} data
 * @param {number} mode
 * @param {() => string} [tmpName]
 */
export function atomicReplaceFile(
  absPath,
  data,
  mode,
  tmpName = () => `.${randomBytes(12).toString("hex")}.tmp`,
) {
  const tmp = join(dirname(absPath), tmpName());
  writeFileSync(tmp, data, { mode, flag: "wx" });
  renameSync(tmp, absPath);
}

/**
 * Strip payload-capable invisible characters from `absPath` in place. Returns
 * true when the file changed (it held a payload {@link scanText} flags), false
 * when {@link scanText} reports nothing.
 *
 * Contract (scan/clean coherence): clean strips exactly what scan flags. A
 * write happens ONLY when `scanText` reports a finding, so the "scan, then
 * clean what scan flagged" workflow never silently rewrites a file scan called
 * clean. A handful of sub-threshold invisible chars (which scan ignores) are
 * left untouched — by design, the scanner's definition of a payload is the
 * single source of truth for what gets removed.
 *
 * Refuses to follow symlinks: instruction files must be regular files, so a
 * symlinked path (which could redirect the write to a target outside the tree)
 * THROWS rather than being written through.
 *
 * The write is atomic (see {@link atomicReplaceFile}): stripped content goes to
 * a temp file in the same directory which is then `rename`d over the original
 * (preserving the original file mode), so a crash mid-write cannot leave a
 * truncated instruction file.
 *
 * Throws if the file cannot be read or written (the caller decides whether an
 * unwritable contaminated file is fatal or falls back to alerting).
 * @param {string} absPath
 * @returns {boolean}
 */
export function cleanFile(absPath) {
  const info = lstatSync(absPath);
  if (info.isSymbolicLink())
    throw new Error(
      `refusing to clean through a symlink (instruction files must be regular files): ${JSON.stringify(
        absPath,
      )}`,
    );

  const original = readFileSync(absPath, "utf-8");
  // Scan is the SSOT for what counts as a payload: don't rewrite a file scan
  // would not flag, even if stripInvisible would technically remove a char.
  // A scan finding (a >=LONG_RUN_THRESHOLD run, or >=SCATTERED_THRESHOLD
  // scattered chars) is past the carve-out's preserve window, so stripInvisible
  // always removes at least one char here — stripped !== original is guaranteed.
  if (scanText(original).length === 0) return false;

  const stripped = stripInvisible(original);
  // info is the lstat above; since the path is confirmed not a symlink, its
  // mode is the regular file's mode. A crash before the rename inside
  // atomicReplaceFile leaves the original intact; after it the new content is
  // fully present. rename/EEXIST errors propagate (fail loud).
  atomicReplaceFile(absPath, stripped, info.mode);
  return true;
}
