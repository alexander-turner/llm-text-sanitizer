/**
 * Semantic-correctness fuzzing for Edit re-anchoring (rehydrate.mjs +
 * view-map.mjs).
 *
 * rehydrate-property.test.mjs fuzzes STRUCTURAL invariants (no mis-anchor,
 * round-trip, never-throws) over one fuzzed edit per generated file. Those
 * hold even if the layer denies edits it should have translated, or passes
 * through edits it should have rewritten — a precision failure the aggregate
 * invariants cannot see, because "deny" and "null" are always legal shapes.
 *
 * This suite fuzzes PRECISION directly: build random multi-line files that
 * interleave labeled constructs, then assert each construct's EXACT fate:
 *
 *   KEEP (must produce updatedInput anchored to exact disk bytes):
 *     - a redacted secret line edited via its placeholder,
 *     - a distinctly-placeholdered secret line,
 *     - a line with an interior zero-width char (hint-free re-anchor),
 *     - an ANSI-colored line (boundary run preserved, interior run replaced);
 *   PASS-THROUGH (must return null, never a rewrite or deny):
 *     - a plain line whose bytes match disk verbatim;
 *   DENY (must refuse with the specific documented reason, never guess):
 *     - an old_string cut mid-placeholder,
 *     - a new_string naming a secret outside the matched span,
 *     - two view-identical lines hiding distinct secrets (ambiguous anchor),
 *     - replace_all across those distinct-secret twins,
 *     - a greedy-alignment collision (ANSI final "m" abutting kept "m"s).
 *
 * Every scenario is grounded in a deterministic case from rehydrate.test.mjs;
 * the fuzzing varies the surrounding document (ordering, neighbors, count) to
 * prove each verdict is decided by the construct itself, not by fixture shape.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { rehydrateRedacted } from "../src/rehydrate.mjs";
import { occurrences } from "../src/view-map.mjs";
import { fcRunOptions, cp } from "./test-helpers.mjs";

const PH = "[REDACTED]";
const PH_PEM = "[REDACTED: Private Key]";
const ZW = cp(0x200b);
const ESC = cp(0x1b);
const GREEN = `${ESC}[32m`;
const RESET = `${ESC}[0m`;

// Assembled at runtime so no complete token literal trips push protection.
// The trailing "q" keeps values prefix-free across indices (…z1q vs …z12q).
const secretFor = (i) => ["hunter2hunter2", `hunter2z${i}q`].join("");

/** Build a redactMap view from cleaned text (same shape the unit tests use). */
function mkView(cleaned, secrets) {
  const hits = [];
  for (const { value, placeholder } of secrets)
    for (const index of occurrences(cleaned, value))
      hits.push({ index, value, placeholder });
  hits.sort((a, b) => a.index - b.index);
  let text = "";
  let last = 0;
  const pairs = [];
  for (const { index, value, placeholder } of hits) {
    text += cleaned.slice(last, index);
    pairs.push({ placeholder, original: value, start: text.length });
    text += placeholder;
    last = index + value.length;
  }
  text += cleaned.slice(last);
  return { text, pairs };
}

/**
 * A labeled construct at document position `i`. Each returns the disk line(s),
 * the model-visible view line(s), and per-construct expectations. Index tags
 * make every KEEP construct's view line unique within the document.
 */
const PIECES = {
  // Redacted secret line: placeholder edit must rehydrate to the real value.
  secret: (i) => ({
    disk: `KEY${i}=${secretFor(i)}`,
    viewLine: `KEY${i}=${PH}`,
    secrets: [{ value: secretFor(i), placeholder: PH }],
  }),
  // Same, under a distinct placeholder text (exercises multi-placeholder docs).
  pem: (i) => ({
    disk: `CERT${i}=${secretFor(i)}`,
    viewLine: `CERT${i}=${PH_PEM}`,
    secrets: [{ value: secretFor(i), placeholder: PH_PEM }],
  }),
  // Interior zero-width char: hint-free edit must re-attach the stripped byte.
  zw: (i) => ({
    disk: `fn${i}(a${ZW}, b);`,
    viewLine: `fn${i}(a, b);`,
    secrets: [],
  }),
  // ANSI color: leading run is a boundary (preserved), reset is interior.
  ansi: (i) => ({
    disk: `${GREEN}log${i}${RESET} ok`,
    viewLine: `log${i} ok`,
    diskAnchor: `log${i}${RESET} ok`, // leading GREEN stays outside the span
    secrets: [],
  }),
  // Plain line: bytes match disk verbatim, layer must not touch the edit.
  plain: (i) => ({
    disk: `plain line ${i} text`,
    viewLine: `plain line ${i} text`,
    secrets: [],
  }),
  // Greedy-alignment collision: the ANSI sequence's final "m" abuts kept
  // "m"s, so the deleted run's placement is ambiguous. Editing across it must
  // be denied, not anchored to a guessed run boundary (pinned deterministic
  // case: "denies when greedy alignment cannot re-anchor unambiguously").
  collide: (i) => ({
    disk: `C${i} m${GREEN}mm`,
    viewLine: `C${i} mmm`,
    secrets: [],
  }),
  // Two view-identical lines hiding DISTINCT secrets: any edit addressed by
  // the shared view text is ambiguous and must be denied, never guessed.
  dupPair: (i) => ({
    disk: `DUP${i}=${secretFor(i)}A\nDUP${i}=${secretFor(i)}B`,
    viewLine: `DUP${i}=${PH}`,
    secrets: [
      { value: `${secretFor(i)}A`, placeholder: PH },
      { value: `${secretFor(i)}B`, placeholder: PH },
    ],
  }),
};

const kindGen = fc.constantFrom(...Object.keys(PIECES));
const docGen = fc
  .array(kindGen, { minLength: 1, maxLength: 8 })
  .map((kinds) => {
    const pieces = kinds.map((kind, i) => ({ kind, ...PIECES[kind](i) }));
    const content = `${pieces.map((p) => p.disk).join("\n")}\n`;
    const secrets = pieces.flatMap((p) => p.secrets);
    return { pieces, content, secrets };
  });

const ioFor = ({ content, secrets }) => ({
  readFile: () => content,
  redactMap: (cleaned) => mkView(cleaned, secrets),
  redact: (text) => mkView(text, secrets).text,
});

const editCall = (doc, old_string, new_string, extra = {}) =>
  rehydrateRedacted(
    "Edit",
    { file_path: "/f", old_string, new_string, ...extra },
    ioFor(doc),
  );

/** Assert an exact translation: rewritten to precisely these disk bytes. */
function assertKeep(out, oldDisk, newDisk, label) {
  assert.ok(out && "updatedInput" in out, `${label}: expected a rewrite`);
  assert.equal(out.updatedInput.old_string, oldDisk, `${label}: old_string`);
  assert.equal(out.updatedInput.new_string, newDisk, `${label}: new_string`);
}

/** Assert a deny carrying the specific documented reason. */
function assertDeny(out, reason, label) {
  assert.ok(out && "deny" in out, `${label}: expected a deny`);
  assert.match(out.deny, reason, `${label}: deny reason`);
  assert.equal(out.updatedInput, undefined, `${label}: deny with rewrite`);
}

describe("semantic-correctness fuzz: rehydrate precision on mixed documents", () => {
  it("each construct's edit gets its exact verdict regardless of neighbors", async () => {
    await fc.assert(
      fc.asyncProperty(docGen, async (doc) => {
        for (const [i, p] of doc.pieces.entries()) {
          if (p.kind === "secret" || p.kind === "pem") {
            // KEEP: placeholder edit rehydrates to the exact on-disk secret.
            assertKeep(
              await editCall(doc, p.viewLine, `${p.viewLine} # rotated`),
              p.disk,
              `${p.disk} # rotated`,
              `${p.kind}#${i} rotate`,
            );
            // KEEP: whole-line deletion anchors to the exact secret bytes.
            assertKeep(
              await editCall(doc, `${p.viewLine}\n`, ""),
              `${p.disk}\n`,
              "",
              `${p.kind}#${i} delete`,
            );
            // DENY: an old_string cut mid-placeholder must never be guessed.
            const [prefix] = p.viewLine.split("]");
            assertDeny(
              await editCall(doc, prefix, "x"),
              /include each placeholder whole/,
              `${p.kind}#${i} mid-placeholder`,
            );
          } else if (p.kind === "zw") {
            // KEEP: hint-free edit re-attaches the interior stripped byte.
            assertKeep(
              await editCall(doc, p.viewLine, `fn${i}(a, b, c);`),
              p.disk,
              `fn${i}(a, b, c);`,
              `zw#${i}`,
            );
          } else if (p.kind === "ansi") {
            // KEEP: interior reset replaced with the span, leading run kept.
            assertKeep(
              await editCall(doc, p.viewLine, `log${i} EDITED`),
              p.diskAnchor,
              `log${i} EDITED`,
              `ansi#${i}`,
            );
          } else if (p.kind === "collide") {
            // DENY: greedy alignment cannot place the deleted run; anchoring
            // anyway could splice the edit across the wrong bytes.
            assertDeny(
              await editCall(doc, p.viewLine, `C${i} nnn`),
              /cannot be\s+re-anchored unambiguously/,
              `collide#${i}`,
            );
          } else if (p.kind === "plain") {
            // PASS-THROUGH: verbatim disk bytes need no translation; a rewrite
            // or deny here would corrupt/block a perfectly ordinary edit.
            assert.equal(
              await editCall(doc, p.viewLine, `edited ${i}`),
              null,
              `plain#${i}`,
            );
          } else {
            // dupPair — DENY both ways: the shared view text hides distinct
            // secrets, so single-target and replace_all edits are ambiguous.
            assertDeny(
              await editCall(doc, p.viewLine, `${p.viewLine}x`),
              /matches 2 locations/,
              `dupPair#${i}`,
            );
            assertDeny(
              await editCall(doc, p.viewLine, `${p.viewLine}x`, {
                replace_all: true,
              }),
              /on-disk bytes differ/,
              `dupPair#${i} replace_all`,
            );
          }
        }

        // DENY: a new_string naming a secret OUTSIDE the matched span must be
        // refused (writing it literally would persist placeholder text; guessing
        // would splice a secret the model never matched).
        const inSpan = doc.pieces.find((p) => p.kind === "secret");
        const outside = doc.pieces.find((p) => p.kind === "pem");
        if (inSpan && outside)
          assertDeny(
            await editCall(
              doc,
              inSpan.viewLine,
              `${inSpan.viewLine}\nCOPY=${outside.viewLine.split("=")[1]}`,
            ),
            /outside\s+the matched old_string/,
            "outside-span placeholder",
          );
      }),
      fcRunOptions({ numRuns: 150 }),
    );
  });
});
