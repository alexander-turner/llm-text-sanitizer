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

import { CHECKS } from "../src/invisible.mjs";
import {
  THREAT_CODEPOINTS,
  IN_SCOPE_MEMBERS,
  acceptedSpellings,
  spellingMatches,
  threat,
} from "./threat-codepoints.mjs";

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

// Entry points that owe SEMANTIC-CORRECTNESS fuzzing, not just structural
// fuzzing: a structural property (never-throws, idempotent, shape-preserved)
// can hold in aggregate while a detector corrupts the wrong leaf or misses a
// specific payload shape — exactly the class of false positive that shipped
// in scanText's scatter floor (fixed alongside this gate). A subset of
// FUZZ_REQUIRED: named internal helpers (isHiddenStyle, decodeRun,
// resolveSpan, alignDeletions, rehydrateNewString, stripInvisibleWithReport,
// deleteVerbatimSpans; urlHost's sibling checkExfilUrl is kept since it's
// independently callable) are exercised only THROUGH their public entry
// point in these suites, so requiring their own name to appear here would be
// a false negative, not a stronger check — the precision property is
// asserted at the entry point.
const SEMANTIC_FUZZ_REQUIRED = [
  "stripInvisible",
  "sanitizeHtml",
  "detectExfil",
  "checkExfilUrl",
  "urlHost",
  "normalizeConfusables",
  "foldConfusables",
  "scanText",
  "classifyPrompt",
  "sanitizeText",
  "sanitizeValue",
  "rehydrateRedacted",
  "occurrences",
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

// A "semantic-fuzz suite" is a fuzz file following the `*-semantic-fuzz.
// test.mjs` naming convention this repo uses for precision fuzzing (fast-check
// generators that interleave known-good and known-bad tokens and assert each
// one's EXACT fate), as opposed to the structural `*-property.test.mjs`
// suites. Naming-based rather than content-sniffed: a heuristic for "asserts
// per-token precision" would be exactly the kind of guard that can't cleanly
// separate the real thing from a lookalike, and CLAUDE.md's guidance is to
// let that kind of check fail open rather than fabricate false confidence.
const semanticFuzzFiles = fuzzFiles.filter((file) =>
  file.name.endsWith("-semantic-fuzz.test.mjs"),
);

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

describe("semantic-fuzz obligation gate", () => {
  it("discovers at least one *-semantic-fuzz.test.mjs suite (gate is not vacuous)", () => {
    assert.ok(
      semanticFuzzFiles.length > 0,
      "no *-semantic-fuzz.test.mjs suites found — the gate would pass vacuously",
    );
    assert.ok(SEMANTIC_FUZZ_REQUIRED.length > 0);
  });

  it("every SEMANTIC_FUZZ_REQUIRED name is also in FUZZ_REQUIRED", () => {
    // Semantic-fuzz coverage is a stricter obligation layered on top of the
    // structural one; a name here that isn't in FUZZ_REQUIRED is a drifted
    // entry, not a real additional target.
    for (const name of SEMANTIC_FUZZ_REQUIRED)
      assert.ok(
        FUZZ_REQUIRED.includes(name),
        `${name} is in SEMANTIC_FUZZ_REQUIRED but not FUZZ_REQUIRED`,
      );
  });

  for (const name of SEMANTIC_FUZZ_REQUIRED) {
    it(`'${name}' is referenced by a *-semantic-fuzz.test.mjs suite`, () => {
      const wordRe = new RegExp(`\\b${name}\\b`);
      const hits = semanticFuzzFiles.filter((file) => wordRe.test(file.code));
      assert.ok(
        hits.length > 0,
        `${name} is a precision-sensitive entry point (structural fuzzing alone ` +
          `can't catch it corrupting the wrong leaf or missing a payload shape) ` +
          `but no *-semantic-fuzz.test.mjs suite references it — add one ` +
          `(see test/invisible-semantic-fuzz.test.mjs for the pattern) or, if the ` +
          `precision property is truly only assertable through a different named ` +
          `entry point, move this name's coverage there and document why here`,
      );
    });
  }
});

// ─── Threat-alphabet domain coverage ─────────────────────────────────────────
// A fuzz target EXISTING (above) does not prove its input DOMAIN reaches the
// dangerous bytes — a uniform unicode draw lands on U+009B ~1-in-a-million, so a
// suite can run forever and never exercise the C1 passthrough class. This block
// asserts each in-scope suite's SOURCE seeds every THREAT_CODEPOINTS member it
// owes (by any hex/escape spelling), the trap the U+009B bug fell through.

const fuzzFileByName = new Map(fuzzFiles.map((file) => [file.name, file]));

describe("threat-alphabet domain coverage", () => {
  it("every invisible-detector category (CHECKS) has a representative cp", () => {
    const represented = new Set(
      THREAT_CODEPOINTS.map((entry) => entry.category),
    );
    for (const [category] of CHECKS)
      assert.ok(
        represented.has(category),
        `CHECKS category '${category}' has no THREAT_CODEPOINTS representative — add one so the gate exercises it`,
      );
  });

  it("every IN_SCOPE suite file actually exists and drives fast-check", () => {
    for (const name of Object.keys(IN_SCOPE_MEMBERS))
      assert.ok(
        fuzzFileByName.has(name),
        `IN_SCOPE names '${name}' but no such fast-check suite was discovered — stale entry or renamed file`,
      );
  });

  it("every IN_SCOPE member is a real THREAT_CODEPOINTS entry (no typo'd cp)", () => {
    for (const [name, members] of Object.entries(IN_SCOPE_MEMBERS))
      for (const cp of members)
        // threat() throws on an unknown cp, so a hand-typed 0x9bb in an in-scope
        // array fails loud here rather than as an unsatisfiable "never seeds" later.
        assert.equal(
          threat(cp).cp,
          cp,
          `IN_SCOPE['${name}'] names 0x${cp.toString(16)}, not in THREAT_CODEPOINTS`,
        );
  });

  it("spellingMatches anchors on hex boundaries (no prefix false positives)", () => {
    // Positive: each accepted spelling of a representative cp matches itself.
    assert.ok(spellingMatches(0x9b, "cp(0x9b)"));
    assert.ok(spellingMatches(0x9b, "cp(0x009b)"));
    assert.ok(spellingMatches(0x07, "cp(0x07)"));
    assert.ok(spellingMatches(0x1f600, "\\u{1f600}"));
    assert.ok(spellingMatches(0x200b, "\\u200b"));
    // Negative: a shorter cp must NOT match as a prefix of a longer hex literal —
    // the U+0007 (0x7) vs the 0x7e ASCII bound is the exact false positive the
    // boundary lookahead exists to kill.
    assert.equal(spellingMatches(0x07, "min: 0x20, max: 0x7e"), false);
    assert.equal(spellingMatches(0x9b, "cp(0x9bc)"), false);
    assert.equal(spellingMatches(0x9b, "\\u009bc"), false);
  });

  for (const [name, members] of Object.entries(IN_SCOPE_MEMBERS)) {
    it(`'${name}' seeds every in-scope threat code point`, () => {
      const file = fuzzFileByName.get(name);
      assert.ok(file, `suite ${name} not found`);
      // A non-empty in-scope set (asserted) over a non-empty source means each
      // pass below is a real per-member check, not a vacuous zero-iteration loop.
      assert.ok(members.length > 0, `${name} has an empty in-scope set`);
      assert.ok(file.code.length > 0, `${name} stripped to empty source`);
      const haystack = file.code.toLowerCase();
      for (const cp of members)
        assert.ok(
          spellingMatches(cp, haystack),
          `${name} never seeds threat cp 0x${cp.toString(16)} ` +
            `(no spelling of ${JSON.stringify(acceptedSpellings(cp))} in its source) — ` +
            `the fuzzer cannot reach it by chance, so the regression class is unguarded`,
        );
    });
  }
});
