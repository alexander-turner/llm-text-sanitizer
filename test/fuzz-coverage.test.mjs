/**
 * SSOT obligation gate: every public function that parses or transforms
 * untrusted input MUST be exercised by at least one property/fuzz suite. This
 * is the same one-test-per-member discipline the enumerated-member tests use
 * (each LINGUISTIC_SCRIPTS / CHECKS / REPORTED_TAGS entry), extended to "every
 * entry point that eats attacker-controlled bytes is fuzzed."
 *
 * Why an obligation gate rather than a coverage percentage: line coverage was
 * already 100% when a real under-stripping bug (U+009B passthrough) shipped,
 * because a passthrough executes the line without violating any asserted
 * invariant. A percentage can't catch "this parser has no security invariant";
 * requiring a named fuzz target for each one can.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import * as invisible from "../src/invisible.mjs";
import * as html from "../src/html.mjs";
import * as index from "../src/index.mjs";
import * as confusables from "../src/confusables.mjs";
import * as instructions from "../src/instructions.mjs";
import * as prompt from "../src/prompt.mjs";
import * as viewMap from "../src/view-map.mjs";
import * as rehydrate from "../src/rehydrate.mjs";
import * as output from "../src/output.mjs";

// Functions that ingest untrusted text/URLs/ranges and so owe a fuzz target.
// Intentionally excluded (documented so the omission is a choice, not a miss):
//   - isSgrOnly, looksLikeHtmlSource, isHiddenOpen, closingTagName: pure
//     short-string predicates with no transform/parse step, covered by example
//     tests and indirectly through their callers.
//   - scanHtmlFragment: has no invariant of its own beyond what the
//     sanitizeHtml round-trip / splice-fidelity properties already assert on
//     its output.
const FUZZ_REQUIRED = [
  "stripInvisible",
  "stripInvisibleWithReport",
  "sanitize",
  "sanitizeHtml",
  "spliceRanges",
  "isHiddenStyle",
  "isHiddenElement",
  "detectExfil",
  "checkExfilUrl",
  "urlHost",
  // Agent-pipeline transforms/parsers over untrusted input (one named fuzz
  // target each — the same obligation extended to the new entry points).
  "normalizeConfusables",
  "foldConfusables",
  "scanText",
  "decodeRun",
  "classifyPrompt",
  "alignDeletions",
  "resolveSpan",
  "rehydrateNewString",
  "occurrences",
  "rehydrateRedacted",
  "sanitizeText",
  "sanitizeValue",
  "deleteVerbatimSpans",
];

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();
const testDir = path.join(repoRoot, "test");

// A "fuzz suite" is any test file that actually drives fast-check. Discovered by
// content, not by name, so a renamed file or a new suite is picked up
// automatically and can't silently drop a required target. This gate file is
// excluded: it names every required function as a string literal (and contains
// the "fc.assert(" sentinel itself), so scanning it would pass vacuously.
const selfName = path.basename(fileURLToPath(import.meta.url));

// Strip import statements and comments so a required name only counts when it
// appears in actual test code — a function listed in an `import {…}` or named
// in a comment is NOT evidence that a property exercises it.
const stripImportsAndComments = (source) =>
  source
    .replace(/^import\b[\s\S]*?from\s+["'][^"']+["'];?[ \t]*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");

const fuzzFiles = readdirSync(testDir)
  .filter((name) => name.endsWith(".test.mjs") && name !== selfName)
  .map((name) => {
    const source = readFileSync(path.join(testDir, name), "utf8");
    return { name, source, code: stripImportsAndComments(source) };
  })
  .filter((file) => file.source.includes("fc.assert("));

const exportedFunctions = new Map(
  [
    invisible,
    html,
    index,
    confusables,
    instructions,
    prompt,
    viewMap,
    rehydrate,
    output,
  ]
    .flatMap((mod) => Object.entries(mod))
    .filter(([, value]) => typeof value === "function"),
);

describe("fuzz-coverage obligation gate", () => {
  it("discovers at least one fast-check suite (gate is not vacuous)", () => {
    assert.ok(
      fuzzFiles.length > 0,
      "no fast-check suites found — the gate would pass vacuously",
    );
    assert.ok(FUZZ_REQUIRED.length > 0);
  });

  for (const name of FUZZ_REQUIRED) {
    it(`'${name}' is a real exported function`, () => {
      assert.equal(
        typeof exportedFunctions.get(name),
        "function",
        `${name} is not an exported function — stale entry in FUZZ_REQUIRED`,
      );
    });

    it(`'${name}' is referenced by a fast-check suite`, () => {
      const wordRe = new RegExp(`\\b${name}\\b`);
      const hits = fuzzFiles.filter((file) => wordRe.test(file.code));
      assert.ok(
        hits.length > 0,
        `${name} handles untrusted input but no property/fuzz suite references it`,
      );
    });
  }
});
