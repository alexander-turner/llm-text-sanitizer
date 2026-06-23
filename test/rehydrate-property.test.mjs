/**
 * Property/fuzz tests for the Edit re-anchoring layer (rehydrate.mjs +
 * view-map.mjs). Example tests pin specific shapes; these pin the INVARIANTS
 * that must hold across fuzzed file contents — secrets, invisible chars, and
 * ANSI sequences interleaved at arbitrary positions:
 *
 *   1. NO MIS-ANCHOR: when the layer rewrites an Edit, the rewritten
 *      old_string exists verbatim on disk AND its sanitized view equals the
 *      old_string the model supplied.
 *   2. ROUND-TRIP: applying the rewritten edit to the disk bytes and
 *      re-sanitizing yields exactly the view-level edit the model intended.
 *   3. NO CORRUPTION otherwise: every other outcome is a pass-through (null)
 *      or an instructive deny — never a rewrite that violates 1-2.
 *   4. NEVER THROWS for arbitrary string inputs given a well-formed io.
 *   5. NO EXPOSURE: a successful rewrite never puts a candidate secret into a
 *      form the next view would reveal.
 *   6. A deny always carries a non-empty reason and no updatedInput.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { rehydrateRedacted } from "../src/rehydrate.mjs";
import { applyLayer1 } from "../src/layer1.mjs";
import { occurrences as occ } from "../src/view-map.mjs";
import { fcRunOptions } from "./test-helpers.mjs";

const SECRET_A = ["hunter2hunter2", "hunter2xA"].join("");
const SECRET_B = ["hunter2hunter2", "hunter2xB"].join("");
const SECRETS = [
  { value: SECRET_A, placeholder: "[REDACTED]" },
  { value: SECRET_B, placeholder: "[REDACTED]" },
];
const ZW = String.fromCharCode(0x200b);
const ESC = String.fromCharCode(0x1b);

/** Build a redactMap view from cleaned text by replacing each secret. */
function mkView(cleaned, secrets) {
  const hits = [];
  for (const { value, placeholder } of secrets)
    for (const index of occ(cleaned, value))
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

// Counterexamples this property has caught, pinned so they replay on EVERY run.
const REGRESSION_EXAMPLES = [[`${ESC}${ESC}[3${ZW}2m[32m\n`, 0, 0, "append"]];

const runOptions = fcRunOptions({
  numRuns: 300,
  examples: REGRESSION_EXAMPLES,
});

const lineArb = fc.constantFrom(
  "alpha beta gamma",
  "x = compute(y)",
  "",
  "mm 32m",
  `PASSWORD=${SECRET_A}`,
  `API_KEY=${SECRET_B}`,
  `TOKEN=${SECRET_A}`,
);
const strippableArb = fc.constantFrom(ZW, `${ESC}[32m`, `${ESC}[0m`, ZW + ZW);

const contentArb = fc
  .record({
    lines: fc.array(lineArb, { minLength: 1, maxLength: 6 }),
    inserts: fc.array(fc.record({ chunk: strippableArb, pos: fc.nat() }), {
      maxLength: 4,
    }),
  })
  .map(({ lines, inserts }) => {
    let content = `${lines.join("\n")}\n`;
    for (const { chunk, pos } of inserts) {
      const at = pos % (content.length + 1);
      content = content.slice(0, at) + chunk + content.slice(at);
    }
    return content;
  });

const fakeIo = (content) => ({
  readFile: () => content,
  redactMap: (text) => mkView(text, SECRETS),
  redact: (text) => mkView(text, SECRETS).text,
});

/** Sanitized view of `disk` exactly as the model would read it. */
function modelView(disk) {
  const { cleaned } = applyLayer1(disk);
  return mkView(cleaned, SECRETS).text;
}

/** The secrets the next view of `disk` would reveal (candidate exposure). */
function exposedInView(disk) {
  const view = modelView(disk);
  return SECRETS.filter((s) => view.includes(s.value));
}

/** Pick a whole-line span of the view as old_string. */
function pickSpan(view, startSeed, lenSeed) {
  const lines = view.split("\n");
  const start = startSeed % lines.length;
  const len = 1 + (lenSeed % (lines.length - start));
  return lines.slice(start, start + len).join("\n");
}

describe("rehydrate: properties", () => {
  it("never mis-anchors and round-trips the model's intended edit", async () => {
    await fc.assert(
      fc.asyncProperty(
        contentArb,
        fc.nat(),
        fc.nat(),
        fc.constantFrom("delete", "append", "replace"),
        async (content, startSeed, lenSeed, mode) => {
          const view = modelView(content);
          const oldS = pickSpan(view, startSeed, lenSeed);
          if (oldS.length === 0) return;
          const replacements = {
            delete: "",
            append: `${oldS}\nEXTRA=1`,
            replace: "replaced line",
          };
          const newS = replacements[mode];

          const result = await rehydrateRedacted(
            "Edit",
            { file_path: "/f", old_string: oldS, new_string: newS },
            fakeIo(content),
          );

          if (result === null) {
            assert.ok(
              content.includes(oldS),
              `null pass-through for a non-matching old_string\n` +
                `content=${JSON.stringify(content)}\nold=${JSON.stringify(oldS)}`,
            );
            return;
          }
          if ("deny" in result) {
            // Invariant 6: a deny is a non-empty reason and carries no rewrite.
            assert.equal(typeof result.deny, "string");
            assert.ok(result.deny.length > 0, "empty deny reason");
            assert.equal(result.updatedInput, undefined);
            return;
          }

          const updatedOld = result.updatedInput.old_string;
          // Invariant 1: anchored to real disk bytes whose view is the input.
          assert.ok(content.includes(updatedOld), "old_string not on disk");
          assert.equal(
            modelView(updatedOld),
            oldS,
            "rewritten old_string does not sanitize back to the model's input",
          );

          // Invariant 2 + 5: round-trip and no-exposure on the unambiguous
          // single-match case.
          if (
            occ(content, updatedOld).length === 1 &&
            occ(view, oldS).length === 1
          ) {
            const newDisk = content.replace(
              updatedOld,
              result.updatedInput.new_string,
            );
            assert.equal(
              modelView(newDisk),
              modelView(view.replace(oldS, newS)),
              "post-edit view differs from the model's intended edit",
            );
            // No secret newly revealed by the rewrite.
            const before = new Set(exposedInView(content).map((s) => s.value));
            for (const s of exposedInView(newDisk))
              assert.ok(
                before.has(s.value),
                "a secret became visible after the rewrite",
              );
          }
        },
      ),
      runOptions,
    );
  });

  it("never throws for arbitrary string inputs given a well-formed io", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string(),
        fc.string(),
        fc.string(),
        fc.constantFrom("Edit", "Write", "NotebookEdit", "Bash"),
        async (content, oldOrContent, newS, tool) => {
          const io = fakeIo(content);
          const inputs = {
            Edit: {
              file_path: "/f",
              old_string: oldOrContent,
              new_string: newS,
            },
            Write: { file_path: "/f", content: oldOrContent },
            NotebookEdit: { notebook_path: "/n", new_source: oldOrContent },
            Bash: { command: oldOrContent },
          };
          const result = await rehydrateRedacted(tool, inputs[tool], io);
          // Invariant 4: the result is one of the three legal shapes.
          assert.ok(
            result === null ||
              typeof result.deny === "string" ||
              typeof result.updatedInput === "object",
          );
          // Invariant 6: a deny carries a reason and no rewrite.
          if (result && "deny" in result) {
            assert.ok(result.deny.length > 0);
            assert.equal(result.updatedInput, undefined);
          }
        },
      ),
      runOptions,
    );
  });
});
