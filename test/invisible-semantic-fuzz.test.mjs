/**
 * Semantic-correctness fuzzing for the ZWNJ/ZWJ carve-out.
 *
 * invisible-property.test.mjs already fuzzes STRUCTURAL invariants
 * (subsequence, idempotence, budget) over arbitrary interleavings of the
 * carve-out's alphabet. Those hold even if the carve-out preserves the WRONG
 * joiner while dropping the right one — e.g. it could stay under budget by
 * keeping an unrelated stray ZWJ elsewhere in the document while corrupting a
 * real emoji it should have left untouched. That's exactly the shape of bug
 * PR-visible history shows slipping past structural fuzzing (an emoji-dense
 * false positive in the sibling instructions.mjs scatter floor).
 *
 * This suite instead fuzzes PRECISION directly: build random documents that
 * interleave known-good, complete constructs (real emoji ZWJ sequences, real
 * linguistic joiners) with known-bad markers (payload joiners, tag chars,
 * zero-width bits), then assert each *specific* good construct survives byte-
 * for-byte and each *specific* bad marker is gone — not just "some invariant
 * held in aggregate."
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { stripInvisible } from "../src/invisible.mjs";
import { fcRunOptions, cp } from "./test-helpers.mjs";

const ZWNJ = cp(0x200c);
const ZWJ = cp(0x200d);
const ZWSP = cp(0x200b);

// Known-good, COMPLETE constructs: each must reappear in the output verbatim,
// unsplit. Mirrors the canonical examples pinned as example tests in
// invisible.test.mjs, reused here as fuzz-generator inputs rather than fixed
// cases.
const KEEP_TOKENS = [
  // 👨‍👩‍👧‍👦 family (3 ZWJ, no selectors)
  cp(0x1f468) + ZWJ + cp(0x1f469) + ZWJ + cp(0x1f467) + ZWJ + cp(0x1f466),
  // 🏳️‍🌈 rainbow flag (VS16 between base and joiner)
  cp(0x1f3f3) + cp(0xfe0f) + ZWJ + cp(0x1f308),
  // 👁️‍🗨️ eye in speech bubble (VS16 on both components)
  cp(0x1f441) + cp(0xfe0f) + ZWJ + cp(0x1f5e8) + cp(0xfe0f),
  // ❤️‍🔥 heart on fire
  cp(0x2764) + cp(0xfe0f) + ZWJ + cp(0x1f525),
  // 👨🏻‍🦰 skin-tone modifier + ZWJ + component
  cp(0x1f468) + cp(0x1f3fb) + ZWJ + cp(0x1f9b0),
  // ❤️ a single pictograph + emoji presentation selector, no joiner at all
  cp(0x2764) + cp(0xfe0f),
  // ❤︎ the same pictograph with the TEXT presentation selector (VS15)
  cp(0x2764) + cp(0xfe0e),
  // "می‌خ" — ZWNJ between Persian (Arabic-script) letters
  cp(0x645) + cp(0x6cc) + ZWNJ + cp(0x62e),
  // "क्‍ष" — ZWJ after a Devanagari virama
  cp(0x915) + cp(0x94d) + ZWJ + cp(0x937),
];

// Known-bad markers: each must be GONE from the output. Wrapped in ASCII
// letters reserved to these tokens (never used in filler) so a substring
// check on the whole token proves the invisible char inside it was actually
// removed, not just that the surrounding letters happen to still be there.
const STRIP_TOKENS = [
  "Q" + ZWJ + "K", // bare ZWJ between plain ASCII — no emoji/script either side
  "Q" + ZWNJ + "K", // bare ZWNJ between plain ASCII
  "Q" + ZWSP + "K", // zero-width space, never preserved
  "Q" + cp(0xe0041) + cp(0xe0070) + "K", // Unicode tag characters (deniable ASCII channel)
];

const pieceGen = fc.oneof(
  fc.constantFrom(...KEEP_TOKENS).map((t) => ({ kind: "keep", t })),
  fc.constantFrom(...STRIP_TOKENS).map((t) => ({ kind: "strip", t })),
  // Benign filler, disjoint from the "Q"/"K" markers above so it can never
  // accidentally complete (or mask the removal of) a strip token.
  fc
    .array(fc.constantFrom(..."0123456789 .,-_".split("")), {
      minLength: 1,
      maxLength: 10,
    })
    .map((cs) => ({ kind: "filler", t: cs.join("") })),
);

const docGen = fc.array(pieceGen, { minLength: 1, maxLength: 8 });

describe("semantic-correctness fuzz: carve-out precision on mixed documents", () => {
  it("every generated real emoji/linguistic construct survives byte-for-byte", () => {
    fc.assert(
      fc.property(docGen, (pieces) => {
        // A space between every piece isolates each token's boundary so no
        // two generated constructs can incidentally fuse into a joined
        // cluster that neither one is on its own — the property is about
        // each construct's OWN correctness, not emergent cross-token joining.
        const text = pieces.map((p) => p.t).join(" ");
        const cleaned = stripInvisible(text);

        for (const p of pieces) {
          if (p.kind === "keep") {
            assert.ok(
              cleaned.includes(p.t),
              `legitimate construct was corrupted or dropped: ${[...p.t]
                .map((c) => `U+${c.codePointAt(0).toString(16)}`)
                .join(" ")}`,
            );
          } else if (p.kind === "strip") {
            assert.ok(
              !cleaned.includes(p.t),
              `payload marker survived stripping: ${[...p.t]
                .map((c) => `U+${c.codePointAt(0).toString(16)}`)
                .join(" ")}`,
            );
          }
        }
      }),
      fcRunOptions(),
    );
  });
});
