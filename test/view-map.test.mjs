/**
 * Example/unit tests for the pure offset engine (view-map.mjs), pinning the
 * security-relevant behaviors and closing every line/branch the property suite
 * (view-map-property.test.mjs) doesn't reach: the empty-span verbatim fast
 * path, the per-placeholder distinct-secret substitution path, and EVERY deny
 * branch of rehydrateNewString.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  occurrences,
  alignDeletions,
  resolveSpan,
  rehydrateNewString,
  pairsToUtf16,
} from "../src/view-map.mjs";

// Secrets assembled at runtime so no complete token literal trips push
// protection; distinct values under the SAME placeholder text exercise the
// ambiguity branches.
const SECRET_A = ["hunter2hunter2", "hunter2xA"].join("");
const SECRET_B = ["hunter2hunter2", "hunter2xB"].join("");
const PH = "[REDACTED]";
const PH_KEY = "[REDACTED: Key]";
const ZW = String.fromCharCode(0x200b);

// ─── occurrences ─────────────────────────────────────────────────────────────

describe("occurrences", () => {
  it("returns non-overlapping ascending indices", () => {
    assert.deepEqual(occurrences("aaaa", "aa"), [0, 2]);
    assert.deepEqual(occurrences("abcabc", "abc"), [0, 3]);
  });

  it("returns [] when the needle is absent", () => {
    assert.deepEqual(occurrences("abc", "z"), []);
  });

  it("a length-1 needle steps by exactly its length", () => {
    // Forward progress comes from the `if (needle === "") return []` guard (which
    // rules out the only zero-length step) plus the `i + needle.length` advance;
    // for a length-1 needle each step is 1, so overlapping single chars are
    // reported once each without revisiting an index.
    assert.deepEqual(occurrences("aaa", "a"), [0, 1, 2]);
    assert.deepEqual(occurrences("aXa", "a"), [0, 2]);
  });
});

// ─── alignDeletions ──────────────────────────────────────────────────────────

describe("alignDeletions", () => {
  it("recovers an interior deleted run sitting immediately before cleaned[start]", () => {
    // content is "a<ZW>bc", cleaned "abc": the run sits before cleaned[1]='b'.
    const dels = alignDeletions(`a${ZW}bc`, "abc");
    assert.deepEqual(dels, [{ start: 1, deleted: ZW }]);
  });

  it("recovers a trailing run as start === cleaned.length", () => {
    const dels = alignDeletions(`ab${ZW}`, "ab");
    assert.deepEqual(dels, [{ start: 2, deleted: ZW }]);
  });

  it("recovers a leading run at start 0", () => {
    const dels = alignDeletions(`${ZW}ab`, "ab");
    assert.deepEqual(dels, [{ start: 0, deleted: ZW }]);
  });

  it("returns [] when nothing was deleted", () => {
    assert.deepEqual(alignDeletions("abc", "abc"), []);
  });

  it("throws when cleaned is not a subsequence of content", () => {
    assert.throws(
      () => alignDeletions("abc", "axc"),
      /layer-1 view is not a subsequence of the file/,
    );
  });

  it("throws when cleaned is longer than content can supply", () => {
    assert.throws(
      () => alignDeletions("ab", "abc"),
      /layer-1 view is not a subsequence of the file/,
    );
  });
});

// ─── resolveSpan ─────────────────────────────────────────────────────────────

// view with no secrets ⇒ view.text === cleaned and pairs empty.
const plainView = (cleaned) => ({ text: cleaned, pairs: [] });

describe("resolveSpan", () => {
  it("maps a span across an interior stripped run, counting it in invisibleBytes", () => {
    const content = `ab${ZW}cd`;
    const cleaned = "abcd";
    const dels = alignDeletions(content, cleaned);
    const res = resolveSpan(content, cleaned, plainView(cleaned), dels, 1, 3);
    assert.equal(res.cleanedText, "bc");
    assert.equal(res.diskText, `b${ZW}c`);
    assert.equal(res.invisibleBytes, 1);
    assert.deepEqual(res.pairs, []);
  });

  it("keeps a run sitting exactly at the span end OUTSIDE the span (preserved)", () => {
    const content = `ab${ZW}cd`;
    const cleaned = "abcd";
    const dels = alignDeletions(content, cleaned);
    // Span [0,2) ends exactly where the run attaches (before cleaned[2]='c').
    const res = resolveSpan(content, cleaned, plainView(cleaned), dels, 0, 2);
    assert.equal(res.cleanedText, "ab");
    assert.equal(res.diskText, "ab");
    assert.equal(res.invisibleBytes, 0);
  });

  it("keeps a run sitting exactly at the span start OUTSIDE the span (preserved)", () => {
    const content = `ab${ZW}cd`;
    const cleaned = "abcd";
    const dels = alignDeletions(content, cleaned);
    // Span [2,4) starts where the run attaches; the run stays before the span.
    const res = resolveSpan(content, cleaned, plainView(cleaned), dels, 2, 4);
    assert.equal(res.cleanedText, "cd");
    assert.equal(res.diskText, "cd");
    assert.equal(res.invisibleBytes, 0);
  });

  it("maps view offsets across a placeholder expansion and returns contained pairs", () => {
    // cleaned: "x" + SECRET_A + "y"; view replaces SECRET_A with PH.
    const cleaned = `x${SECRET_A}y`;
    const view = {
      text: `x${PH}y`,
      pairs: [{ placeholder: PH, original: SECRET_A, start: 1 }],
    };
    const res = resolveSpan(cleaned, cleaned, view, [], 0, view.text.length);
    assert.equal(res.cleanedText, cleaned);
    assert.equal(res.diskText, cleaned);
    assert.equal(res.invisibleBytes, 0);
    assert.deepEqual(res.pairs, view.pairs);
  });

  it("returns null when the span START cuts strictly inside a placeholder", () => {
    const cleaned = `x${SECRET_A}y`;
    const view = {
      text: `x${PH}y`,
      pairs: [{ placeholder: PH, original: SECRET_A, start: 1 }],
    };
    // Offset 2 is strictly inside the placeholder [1, 1+PH.length).
    const res = resolveSpan(cleaned, cleaned, view, [], 2, view.text.length);
    assert.equal(res, null);
  });

  it("returns null when the span END cuts strictly inside a placeholder", () => {
    const cleaned = `x${SECRET_A}y`;
    const view = {
      text: `x${PH}y`,
      pairs: [{ placeholder: PH, original: SECRET_A, start: 1 }],
    };
    const res = resolveSpan(cleaned, cleaned, view, [], 0, 2);
    assert.equal(res, null);
  });

  it("returns only the pairs wholly inside the span (the trailing one is dropped)", () => {
    // Two placeholders; span covers only the first. The filter keeps pairs
    // wholly inside [viewStart, viewEnd).
    const cleaned = `${SECRET_A} ${SECRET_B}`;
    const view = {
      text: `${PH} ${PH_KEY}`,
      pairs: [
        { placeholder: PH, original: SECRET_A, start: 0 },
        { placeholder: PH_KEY, original: SECRET_B, start: PH.length + 1 },
      ],
    };
    const res = resolveSpan(cleaned, cleaned, view, [], 0, PH.length);
    assert.deepEqual(res.pairs, [view.pairs[0]]);
  });
});

// ─── rehydrateNewString ──────────────────────────────────────────────────────

describe("rehydrateNewString", () => {
  it("verbatim fast path: empty span leaves new_string unchanged", () => {
    const out = rehydrateNewString("", "plain new text", [], []);
    assert.deepEqual(out, { text: "plain new text", secrets: [] });
  });

  it("verbatim fast path: an empty span passes new_string through even when it has plain placeholder-shaped-but-unknown text", () => {
    const out = rehydrateNewString("old", "no placeholders here", [], []);
    assert.deepEqual(out, { text: "no placeholders here", secrets: [] });
  });

  it("1:1 positional map when the new placeholder sequence equals the span's", () => {
    const spanPairs = [
      { placeholder: PH, original: SECRET_A, start: 0 },
      { placeholder: PH_KEY, original: SECRET_B, start: 100 },
    ];
    const oldS = `${PH}|${PH_KEY}`;
    const newS = `before ${PH} mid ${PH_KEY} after`;
    const out = rehydrateNewString(oldS, newS, spanPairs, spanPairs);
    assert.equal(out.text, `before ${SECRET_A} mid ${SECRET_B} after`);
    assert.deepEqual(out.secrets, [SECRET_A, SECRET_B]);
  });

  it("per-placeholder distinct-secret substitution when the sequence does NOT match 1:1", () => {
    // Span has ONE pair under PH; new_string uses PH twice. The fast-path
    // sequence-equality check fails (counts differ), so it falls to the
    // per-placeholder branch: PH maps to its single distinct secret everywhere.
    const spanPairs = [{ placeholder: PH, original: SECRET_A, start: 0 }];
    const oldS = PH;
    const newS = `${PH} and again ${PH}`;
    const out = rehydrateNewString(oldS, newS, spanPairs, spanPairs);
    assert.equal(out.text, `${SECRET_A} and again ${SECRET_A}`);
    assert.deepEqual(out.secrets, [SECRET_A]);
  });

  it("DENY: new_string names a secret redacted OUTSIDE the matched old_string", () => {
    const filePairs = [{ placeholder: PH, original: SECRET_A, start: 0 }];
    const out = rehydrateNewString("literal old", `note ${PH}`, [], filePairs);
    assert.equal("text" in out, false);
    assert.equal(typeof out.deny, "string");
    assert.ok(out.deny.length > 0);
    assert.match(out.deny, /outside the matched old_string/);
  });

  it("ALLOW: a placeholder-shaped literal the model matched verbatim in old_string is not a deny", () => {
    // filePairs has PH, but old_string also contains the literal PH text, so it
    // is treated as literal file text the model matched verbatim (continue).
    const filePairs = [{ placeholder: PH, original: SECRET_A, start: 0 }];
    const out = rehydrateNewString(
      `the literal ${PH} marker`,
      `the literal ${PH} marker, edited`,
      [],
      filePairs,
    );
    assert.equal(out.text, `the literal ${PH} marker, edited`);
    assert.deepEqual(out.secrets, []);
  });

  it("DENY: literal placeholder text collides with a real secret sharing that placeholder", () => {
    // Span produces ONE secret under PH (produced=1); old_string contains PH
    // TWICE (occurrences=2 > produced). Cannot tell which occurrence in
    // new_string is the literal vs the secret.
    const spanPairs = [{ placeholder: PH, original: SECRET_A, start: 0 }];
    const oldS = `${PH} literal ${PH}`;
    const newS = `${PH} literal ${PH}`;
    const out = rehydrateNewString(oldS, newS, spanPairs, spanPairs);
    assert.equal("text" in out, false);
    assert.equal(typeof out.deny, "string");
    assert.ok(out.deny.length > 0);
    assert.match(out.deny, /mixes literal/);
  });

  it("DENY: multiple distinct secrets share one placeholder and new_string changes their count/order", () => {
    // Two pairs under the SAME placeholder PH but DISTINCT originals. The
    // new_string has a single PH occurrence (count differs from the span's 2),
    // so the fast path is skipped and the per-placeholder branch sees >1 value.
    const spanPairs = [
      { placeholder: PH, original: SECRET_A, start: 0 },
      { placeholder: PH, original: SECRET_B, start: 100 },
    ];
    const oldS = `${PH}|${PH}`;
    const newS = `just ${PH}`;
    const out = rehydrateNewString(oldS, newS, spanPairs, spanPairs);
    assert.equal("text" in out, false);
    assert.equal(typeof out.deny, "string");
    assert.ok(out.deny.length > 0);
    assert.match(out.deny, /multiple distinct secrets/);
  });

  it("filePairs deduplicates: a placeholder absent from new_string is skipped", () => {
    // filePairs references PH_KEY but new_string never mentions it ⇒ the
    // `!newS.includes(phText)` guard continues past it without denying.
    const filePairs = [{ placeholder: PH_KEY, original: SECRET_B, start: 0 }];
    const out = rehydrateNewString("old", "new text only", [], filePairs);
    assert.deepEqual(out, { text: "new text only", secrets: [] });
  });
});

// ─── pairsToUtf16 (code-point → UTF-16 start normalization) ──────────────────

describe("pairsToUtf16", () => {
  it("is the identity for BMP-only text (code point == UTF-16 unit)", () => {
    // No astral chars: every start already equals its UTF-16 offset.
    const text = `key: ${PH_KEY} tail`;
    const pairs = [{ placeholder: PH_KEY, original: "AKIA1234", start: 5 }];
    assert.deepEqual(pairsToUtf16(text, pairs), pairs);
  });

  it("shifts a start right by one unit per astral char before it", () => {
    // Two emoji (astral, 2 UTF-16 units each) precede the placeholder, so its
    // code-point start (3) maps to UTF-16 offset 3 + 2 = 5.
    const text = `🔑🔑 ${PH_KEY}`;
    const cpStart = Array.from(text).indexOf("["); // 3 code points in
    assert.equal(cpStart, 3);
    const utf16Start = text.indexOf("["); // 5 UTF-16 units in
    assert.equal(utf16Start, 5);
    const out = pairsToUtf16(text, [
      { placeholder: PH_KEY, original: "AKIA1234", start: cpStart },
    ]);
    assert.equal(out[0].start, utf16Start);
    assert.equal(
      text.slice(out[0].start, out[0].start + PH_KEY.length),
      PH_KEY,
    );
  });

  it("returns the empty pairs array unchanged", () => {
    const empty = [];
    assert.equal(pairsToUtf16("🔑 no pairs", empty), empty);
  });

  it("normalizes several pairs, each by the astral count preceding it", () => {
    const text = `🔑 ${PH_KEY} 🔑 ${PH}`;
    const cp = Array.from(text);
    const s1 = cp.indexOf("["); // first placeholder, code-point offset
    const s2 = cp.indexOf("[", s1 + 1); // second placeholder, code-point offset
    const out = pairsToUtf16(text, [
      { placeholder: PH_KEY, original: "AKIA1", start: s1 },
      { placeholder: PH, original: "AKIA2", start: s2 },
    ]);
    assert.equal(
      text.slice(out[0].start, out[0].start + PH_KEY.length),
      PH_KEY,
    );
    assert.equal(text.slice(out[1].start, out[1].start + PH.length), PH);
  });
});
