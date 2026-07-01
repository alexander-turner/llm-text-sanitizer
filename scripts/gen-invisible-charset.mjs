#!/usr/bin/env node
/**
 * Generate the language-agnostic invisible-charset SSOT from invisible.mjs.
 *
 * The authoritative definition of the payload-capable invisible characters lives
 * in `src/invisible.mjs` (the `VS` and `BLANK_NON_CF` exports plus the dynamic
 * `\p{Cf}` category). A non-JS consumer — e.g. the Python `agent-secret-redactor`
 * engine — cannot import that module, and must NOT hand-copy the set: a fork is a
 * silent security regression (a code point added here but not there lets a key
 * spliced with it escape one layer). So this script emits the NON-Cf "extra" code
 * points (variation selectors, blank-rendering fillers, zero-width combining
 * marks) as JSON that every language reads. `Cf` stays dynamic — each consumer
 * resolves it from its own Unicode database — because it is a standard category,
 * not a hand-curated list.
 *
 * Writes `python/agent_input_sanitizer/data/invisible-charset.json` (packaged
 * with the Python client). Run from the repo root: `node scripts/gen-invisible-charset.mjs`.
 * `tests/invisible-charset.test.mjs` fails CI if the committed file drifts from
 * this output.
 */
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { VS, BLANK_NON_CF } from "../src/invisible.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));

/** Sorted, de-duped code points of every char in the given strings. */
export function extraCodepoints() {
  const cps = new Set();
  for (const s of [VS, BLANK_NON_CF])
    for (const ch of s) cps.add(ch.codePointAt(0));
  return [...cps].sort((a, b) => a - b);
}

export function charsetDoc() {
  return {
    _comment:
      "SSOT for the payload-capable invisible code points that are NOT Unicode " +
      "general-category Cf, generated from src/invisible.mjs (VS + BLANK_NON_CF) by " +
      "scripts/gen-invisible-charset.mjs. The full deletion set is these code points " +
      "UNION every Cf code point (resolved dynamically per language, since Cf is a " +
      "standard category). Consumers in other languages read this file instead of " +
      "forking the list — a fork is a silent security regression.",
    extra_codepoints: extraCodepoints(),
  };
}

export const OUTPUT_PATH = join(
  __dirname,
  "..",
  "python",
  "agent_input_sanitizer",
  "data",
  "invisible-charset.json",
);

function main() {
  writeFileSync(OUTPUT_PATH, JSON.stringify(charsetDoc(), null, 2) + "\n");
  console.log(`wrote ${OUTPUT_PATH} (${extraCodepoints().length} code points)`);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
