/**
 * Contract test for the sharded mutation-testing matrix.
 *
 * `.github/mutation-shards.json` partitions the mutation run across parallel CI
 * jobs (line ranges for the big files, whole files for the rest). Stryker's
 * config mutates `src/*.mjs`, but the sharded workflow enumerates files
 * explicitly — so a new source file, or a gap in the line ranges, would be
 * mutated by nobody and the gate would silently fail open over uncovered code.
 *
 * This guards both holes: every `src/*.mjs` file is covered by exactly the shard
 * set, and the line ranges of any split file tile [1, EOF) with no gap or
 * overlap, ending open (so growth past the last boundary is still mutated).
 */
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";
import { describe, it } from "node:test";

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();

// The open-ended sentinel the last range of a split file must use so the tail of
// the file is always mutated even after it grows. Kept in lockstep with
// .github/mutation-shards.json.
const EOF_SENTINEL = 99999;

const shards = JSON.parse(
  readFileSync(join(repoRoot, ".github", "mutation-shards.json"), "utf8"),
);

/** Parse "src/a.mjs:1-50,src/b.mjs" into [{file, range?}, ...]. */
const parseMutate = (mutate) =>
  mutate.split(",").map((entry) => {
    const [file, range] = entry.split(":");
    if (!range) return { file };
    const [start, end] = range.split("-").map(Number);
    return { file, start, end };
  });

describe("mutation shard matrix", () => {
  it("covers exactly the src/*.mjs files Stryker mutates", () => {
    const onDisk = readdirSync(join(repoRoot, "src"))
      .filter((f) => f.endsWith(".mjs"))
      .map((f) => `src/${f}`)
      .sort();

    const inShards = [
      ...new Set(
        shards.flatMap((s) => parseMutate(s.mutate).map((e) => e.file)),
      ),
    ].sort();

    assert.deepEqual(
      inShards,
      onDisk,
      "shard file set must equal src/*.mjs (add/remove a shard when a source file is added/removed)",
    );
  });

  it("tiles every split file's line ranges with no gap or overlap, ending open", () => {
    const byFile = new Map();
    for (const shard of shards) {
      for (const entry of parseMutate(shard.mutate)) {
        if (entry.start === undefined) continue;
        if (!byFile.has(entry.file)) byFile.set(entry.file, []);
        byFile.get(entry.file).push(entry);
      }
    }

    assert.ok(byFile.size > 0, "expected at least one line-range-split file");

    for (const [file, ranges] of byFile) {
      ranges.sort((a, b) => a.start - b.start);
      assert.equal(ranges[0].start, 1, `${file}: first range must start at 1`);
      for (let i = 1; i < ranges.length; i++) {
        assert.equal(
          ranges[i].start,
          ranges[i - 1].end + 1,
          `${file}: range ${i} must start one line after the previous range ends (no gap/overlap)`,
        );
      }
      assert.ok(
        ranges.at(-1).end >= EOF_SENTINEL,
        `${file}: last range must end open (>= ${EOF_SENTINEL}) so the tail is always mutated`,
      );
    }
  });
});
