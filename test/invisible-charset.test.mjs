/**
 * Drift guard: the generated invisible-charset SSOT
 * (`python/agent_input_sanitizer/data/invisible-charset.json`) must equal what
 * `scripts/gen-invisible-charset.mjs` produces from `src/invisible.mjs` right
 * now. The JSON is what non-JS consumers (the Python `agent-secret-redactor`
 * engine) read instead of forking the invisible-character set; if it drifts from
 * `invisible.mjs`, a key spliced with a newly-added code point escapes one layer.
 *
 * Regenerate with `node scripts/gen-invisible-charset.mjs` when `VS` /
 * `BLANK_NON_CF` change.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  extraCodepoints,
  OUTPUT_PATH,
} from "../scripts/gen-invisible-charset.mjs";
import { VS, BLANK_NON_CF } from "../src/invisible.mjs";

describe("invisible-charset SSOT", () => {
  it("committed JSON equals the freshly generated code points", () => {
    const committed = JSON.parse(readFileSync(OUTPUT_PATH, "utf8"));
    assert.deepEqual(committed.extra_codepoints, extraCodepoints());
  });

  it("covers every VS and BLANK_NON_CF code point (no member dropped)", () => {
    const generated = new Set(extraCodepoints());
    for (const s of [VS, BLANK_NON_CF])
      for (const ch of s)
        assert.ok(
          generated.has(ch.codePointAt(0)),
          `U+${ch.codePointAt(0).toString(16)} missing from the SSOT`,
        );
    // And nothing extra: exactly the union, no more.
    const expected = new Set();
    for (const s of [VS, BLANK_NON_CF])
      for (const ch of s) expected.add(ch.codePointAt(0));
    assert.equal(generated.size, expected.size);
  });
});
