/**
 * Guards the cross-language golden against drift.
 *
 * `tests/golden.json` is a recording of `sanitize`'s output over the shared
 * corpus (`tests/golden-corpus.json`), consumed by the Python client's
 * byte-for-byte test. It is a derived artifact of `src/`, so if `src/` changes
 * the committed golden must be regenerated in the same commit — otherwise the
 * Python golden test asserts against a stale recording. This re-runs the
 * generator in `--check` mode and fails if the committed file is stale.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..");

describe("cross-language golden corpus", () => {
  it("committed tests/golden.json is in lockstep with src/ (regenerate if this fails)", () => {
    // Exit 0 == fresh; non-zero == stale, with a message on stderr.
    execFileSync(
      process.execPath,
      [join(here, "generate-golden.mjs"), "--check"],
      {
        cwd: repoRoot,
        stdio: "pipe",
      },
    );
  });

  it("every corpus case is recorded for both plain and html", () => {
    const corpus = JSON.parse(
      readFileSync(join(repoRoot, "tests", "golden-corpus.json"), "utf8"),
    );
    const golden = JSON.parse(
      readFileSync(join(repoRoot, "tests", "golden.json"), "utf8"),
    );
    assert.ok(corpus.cases.length > 0, "corpus must be non-empty");
    assert.equal(golden.cases.length, corpus.cases.length);
    const corpusNames = corpus.cases.map((c) => c.name);
    const goldenNames = golden.cases.map((c) => c.name);
    assert.deepEqual(goldenNames, corpusNames);
    for (const c of golden.cases) {
      assert.ok(c.plain && Array.isArray(c.plain.cleaned), `${c.name} plain`);
      assert.ok(c.html && Array.isArray(c.html.cleaned), `${c.name} html`);
    }
  });
});
