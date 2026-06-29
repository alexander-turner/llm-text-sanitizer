#!/usr/bin/env node
/**
 * Aggregate the JSON reports emitted by the sharded mutation jobs into one
 * global mutation score and apply the break threshold.
 *
 * Each shard runs Stryker over a disjoint slice of the codebase (line ranges of
 * the big files, whole files for the rest) with `thresholds.break` nulled, so no
 * single shard knows the project-wide score. This script sums the per-mutant
 * verdicts across every shard's `mutation.json`, computes the same mutation
 * score Stryker would, and fails the build if it falls under the break
 * threshold read from `stryker.conf.json` (single source of truth — the shards
 * derive their config from the same file, so the gate can never drift from it).
 *
 * Usage: node aggregate-mutation.mjs <reports-dir>
 * Exits non-zero when the score is under threshold or when no reports are found
 * (a vacuous pass would silently disable the gate).
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const reportsDir = process.argv[2];
if (!reportsDir) {
  throw new Error("usage: aggregate-mutation.mjs <reports-dir>");
}

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const strykerConf = JSON.parse(
  readFileSync(join(repoRoot, "stryker.conf.json"), "utf8"),
);
const breakThreshold = strykerConf.thresholds?.break;
if (typeof breakThreshold !== "number") {
  throw new Error(
    `stryker.conf.json thresholds.break must be a number, got ${JSON.stringify(breakThreshold)}`,
  );
}

// Detected mutants are caught by the suite; undetected slip through. Mutants
// that never produced a real verdict (compile/runtime errors, ignored, pending)
// are excluded from the score, exactly as Stryker does.
const DETECTED = new Set(["Killed", "Timeout"]);
const UNDETECTED = new Set(["Survived", "NoCoverage"]);

const reportFiles = readdirSync(reportsDir, { recursive: true })
  .map((entry) => join(reportsDir, entry.toString()))
  .filter((p) => p.endsWith("mutation.json"));

// Every shard uploads exactly one report. Demand one per shard so a silently
// missing artifact fails the gate loudly instead of scoring a subset as if it
// were the whole project.
const shardCount = JSON.parse(
  readFileSync(join(repoRoot, ".github", "mutation-shards.json"), "utf8"),
).length;
if (reportFiles.length !== shardCount) {
  throw new Error(
    `Expected ${shardCount} shard report(s) (one per shard) but found ${reportFiles.length} under ${reportsDir}; refusing to gate on a partial result.`,
  );
}

const counts = {};
let total = 0;
for (const file of reportFiles) {
  const report = JSON.parse(readFileSync(file, "utf8"));
  for (const path of Object.keys(report.files)) {
    for (const mutant of report.files[path].mutants) {
      counts[mutant.status] = (counts[mutant.status] || 0) + 1;
      total += 1;
    }
  }
}

const detected = [...DETECTED].reduce((n, s) => n + (counts[s] || 0), 0);
const undetected = [...UNDETECTED].reduce((n, s) => n + (counts[s] || 0), 0);
const scored = detected + undetected;
const score = scored === 0 ? 0 : (detected / scored) * 100;

const lines = [
  `Aggregated ${reportFiles.length} shard report(s): ${total} mutants total.`,
  `Status breakdown: ${JSON.stringify(counts)}`,
  `Mutation score: ${score.toFixed(2)}% (break threshold ${breakThreshold}%).`,
];
const summary = lines.join("\n");
process.stdout.write(`${summary}\n`);
if (process.env.GITHUB_STEP_SUMMARY) {
  const { appendFileSync } = await import("node:fs");
  appendFileSync(
    process.env.GITHUB_STEP_SUMMARY,
    `### Mutation testing\n\n${lines.map((l) => `- ${l}`).join("\n")}\n`,
  );
}

if (score < breakThreshold) {
  process.stderr.write(
    `Final mutation score ${score.toFixed(2)} under breaking threshold ${breakThreshold}.\n`,
  );
  process.exit(1);
}
