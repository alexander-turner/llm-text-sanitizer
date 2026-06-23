/**
 * Property/composition fuzzer for the pure user-prompt verdict
 * (src/prompt.mjs). The example suite (prompt.test.mjs) pins specific shapes;
 * these GENERALIZE the structural invariants over fuzzed input:
 *
 *   - classifyPrompt NEVER throws on arbitrary unicode / astral / lone-surrogate
 *     input; its action is always one of pass | note | block.
 *   - a block always carries a non-empty string reason; pass/note never do.
 *   - a prompt with no ANSI and invisibles below threshold always passes.
 *
 * Control bytes are built with String.fromCodePoint, never pasted raw.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { classifyPrompt } from "../src/prompt.mjs";
import { SCATTERED_THRESHOLD } from "../src/invisible.mjs";
import { fcRunOptions, cp } from "./test-helpers.mjs";

const runOptions = fcRunOptions({ numRuns: 500 });
const check = (arbitrary, predicate) =>
  fc.assert(fc.property(arbitrary, predicate), runOptions);

const ACTIONS = new Set(["pass", "note", "block"]);

// Any single code point except the surrogate range (so .map(fromCodePoint)
// never throws); lone surrogates are injected separately as raw code units.
const unicodeChar = fc
  .integer({ min: 0, max: 0x10ffff })
  .filter((c) => c < 0xd800 || c > 0xdfff)
  .map((c) => String.fromCodePoint(c));
const loneSurrogate = fc
  .integer({ min: 0xd800, max: 0xdfff })
  .map((c) => String.fromCharCode(c));
// Payload-capable invisibles across each CHECKS category, plus ESC.
const invisibleChar = fc.constantFrom(
  ...[0x200b, 0x200d, 0x2060, 0xfeff, 0x00ad, 0xfe01, 0x3164, 0xe0041].map(
    (c) => cp(c),
  ),
);
const escChar = fc.constant(cp(0x1b));
const adversarialChar = fc.oneof(
  unicodeChar,
  loneSurrogate,
  invisibleChar,
  escChar,
);
const adversarialText = fc
  .array(adversarialChar, { maxLength: 80 })
  .map((parts) => parts.join(""));

// Printable ASCII only — no ESC, no invisible — so on its own this is a clean
// pass. (Below the scattered/long-run thresholds, no ANSI.)
const visible = fc
  .array(fc.integer({ min: 0x20, max: 0x7e }))
  .map((codes) => codes.map((code) => String.fromCharCode(code)).join(""));

describe("classifyPrompt (property): totality", () => {
  it("never throws on adversarial unicode; action is always pass | note | block; block carries a non-empty string reason", () => {
    check(
      fc.oneof(adversarialText, fc.string({ unit: "binary" })),
      (prompt) => {
        const verdict = classifyPrompt(prompt);
        assert.ok(ACTIONS.has(verdict.action), `bad action: ${verdict.action}`);
        if (verdict.action === "block") {
          assert.equal(typeof verdict.reason, "string");
          assert.ok(verdict.reason.length > 0, "empty block reason");
        } else {
          assert.equal(verdict.reason, undefined);
        }
      },
    );
  });

  it("empty prompt always passes", () => {
    assert.deepEqual(classifyPrompt(""), { action: "pass" });
  });
});

describe("classifyPrompt (property): clean text below threshold passes", () => {
  it("no ANSI and < SCATTERED_THRESHOLD scattered invisibles (no run) always passes", () => {
    const invBelow = fc.constantFrom(cp(0x200b), cp(0x00ad), cp(0x2060));
    check(
      fc.tuple(
        visible,
        invBelow,
        fc.integer({ min: 0, max: SCATTERED_THRESHOLD - 1 }),
        visible,
      ),
      ([head, inv, count, tail]) => {
        // One invisible between visible 'x' chars: no run reaches the long-run
        // threshold, and the total stays under the scattered threshold.
        const scattered = Array.from({ length: count }, () => `x${inv}`).join(
          "",
        );
        assert.deepEqual(classifyPrompt(head + scattered + tail), {
          action: "pass",
        });
      },
    );
  });
});
