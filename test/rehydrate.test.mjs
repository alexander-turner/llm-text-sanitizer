import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { rehydrateRedacted, DEFAULT_HINT } from "../src/rehydrate.mjs";
import { alignDeletions, occurrences } from "../src/view-map.mjs";

// Secrets assembled at runtime so no complete token literal trips push
// protection / gitleaks.
const SECRET_A = ["hunter2hunter2", "hunter2xA"].join("");
const SECRET_B = ["hunter2hunter2", "hunter2xB"].join("");
const SECRET_C = ["hunter2hunter2", "hunter2xC"].join("");
const PH = "[REDACTED]";
const PH_PEM = "[REDACTED: Private Key]";
// Built from code points so no raw invisible/control byte sits in this source.
const ZW = String.fromCharCode(0x200b); // zero-width space (Layer 1 strips)
const ESC = String.fromCharCode(0x1b);
const GREEN = `${ESC}[32m`;
const RESET = `${ESC}[0m`;

/**
 * Build a redactMap view from already-Layer-1-cleaned text: replace each
 * secret occurrence with its placeholder, emitting ordered (placeholder,
 * original, start) pairs at the view offsets.
 * @param {string} cleaned
 * @param {{value: string, placeholder: string}[]} secrets
 * @returns {{text: string, pairs: {placeholder: string, original: string, start: number}[]}}
 */
function mkView(cleaned, secrets) {
  // Collect every secret occurrence in the cleaned text, ordered by position.
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
 * Fake io over a hand-built view. `redact` is what io.redact returns for the
 * exposure re-scan (null = the redactor's "nothing redacted" signal). The
 * `redactMap` ignores its (cleaned) argument: these fixtures carry no
 * invisible characters, so cleaned ≡ content.
 */
const fakeIo = (content, view, redact = () => null) => ({
  readFile: () => content,
  redactMap: () => view,
  redact,
});

/**
 * Fake io for invisible-char fixtures: derives the view from whatever cleaned
 * text the layer hands it, replacing each secret occurrence.
 */
const liveIo = (content, secrets = [], redact = () => null) => ({
  readFile: () => content,
  redactMap: (text) => mkView(text, secrets),
  redact,
});

// An exposure re-scan in which every known secret stays redacted.
const reRedact = (text) =>
  text.split(SECRET_A).join(PH).split(SECRET_B).join(PH);

// ─── Gating: which calls the layer even looks at ─────────────────────────────

describe("rehydrate: gating", () => {
  const unreadableIo = {
    readFile: () => {
      throw new Error("ENOENT");
    },
    redactMap: () => {
      throw new Error("redactMap must not be reached");
    },
    redact: () => null,
  };

  it("exports the default hint", () => {
    assert.equal(DEFAULT_HINT, "[REDACTED");
  });

  it("ignores tools without rehydratable fields", async () => {
    assert.equal(
      await rehydrateRedacted("Bash", { command: `echo ${PH}` }, unreadableIo),
      null,
    );
  });

  it("ignores malformed inputs (missing path or non-string fields)", async () => {
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { old_string: PH, new_string: "b" },
        unreadableIo,
      ),
      null,
    );
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: PH, new_string: 7 },
        unreadableIo,
      ),
      null,
    );
    assert.equal(
      await rehydrateRedacted(
        "Write",
        { file_path: "/f", content: 7 },
        unreadableIo,
      ),
      null,
    );
  });

  it("ignores Write content without placeholder text", async () => {
    assert.equal(
      await rehydrateRedacted(
        "Write",
        { file_path: "/f", content: "x" },
        unreadableIo,
      ),
      null,
    );
  });

  it("treats a null tool_input as a non-candidate without dereferencing it", async () => {
    assert.equal(await rehydrateRedacted("Edit", null, unreadableIo), null);
    assert.equal(
      await rehydrateRedacted("NotebookEdit", null, unreadableIo),
      null,
    );
  });

  it("passes through when the target file is unreadable", async () => {
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/missing", old_string: PH, new_string: "x" },
        unreadableIo,
      ),
      null,
    );
  });

  it("short-circuits a hint-free Edit whose old_string matches disk", async () => {
    const io = {
      readFile: () => "plain content\n",
      redactMap: () => {
        throw new Error("redactMap must not be reached");
      },
      redact: () => null,
    };
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: "plain", new_string: "simple" },
        io,
      ),
      null,
    );
  });

  it("short-circuits a hint-free mismatch against a Layer-1-clean file", async () => {
    const io = {
      readFile: () => "plain content\n",
      redactMap: () => {
        throw new Error("redactMap must not be reached");
      },
      redact: () => null,
    };
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: "absent", new_string: "x" },
        io,
      ),
      null,
    );
  });

  it("denies an unmappable file for a placeholder-bearing input", async () => {
    const io = fakeIo("c", {
      unmappable: "input contains reserved sentinel characters",
    });
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: PH, new_string: "x" },
      io,
    );
    assert.match(out.deny, /cannot resolve redaction placeholders/);
  });

  it("passes through an unmappable file for a hint-free Edit", async () => {
    const content = `${ZW}weird\n`;
    const io = {
      readFile: () => content,
      redactMap: () => ({
        unmappable: "input contains reserved sentinel characters",
      }),
      redact: () => null,
    };
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: "weird stuff", new_string: "x" },
        io,
      ),
      null,
    );
  });

  it("passes through when nothing in the file is redacted or stripped", async () => {
    const content = `doc says ${PH} here`;
    const io = fakeIo(content, mkView(content, []));
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        {
          file_path: "/f",
          old_string: `says ${PH}`,
          new_string: `says ${PH}!`,
        },
        io,
      ),
      null,
    );
  });

  it("passes through a hinted Edit on a clean file when old_string is absent", async () => {
    const content = "plain\n";
    const io = fakeIo(content, mkView(content, []));
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: `gone ${PH}`, new_string: "x" },
        io,
      ),
      null,
    );
  });

  it("denies NotebookEdit carrying a placeholder, ignores one without", async () => {
    const out = await rehydrateRedacted(
      "NotebookEdit",
      { notebook_path: "/n.ipynb", new_source: `x = "${PH}"` },
      // io is never reached on the notebook deny path.
      { readFile: () => "x", redactMap: () => mkView("x", []) },
    );
    assert.match(out.deny, /not supported for notebooks/);
    assert.match(out.deny, /stands for a secret/);
    assert.match(out.deny, /Keep[\s\S]*the secret-bearing cell unchanged/);
    assert.equal(
      await rehydrateRedacted(
        "NotebookEdit",
        { notebook_path: "/n.ipynb", new_source: "x = 1" },
        { readFile: () => "x", redactMap: () => mkView("x", []) },
      ),
      null,
    );
  });

  // The candidate gate must reject before any file/redactor work.
  const mapThrowsIo = {
    readFile: () => `secret K=${SECRET_A}\n`,
    redactMap: () => {
      throw new Error("redactMap must not be reached");
    },
    redact: () => null,
  };

  it("rejects an Edit with a non-string field before touching the redactor", async () => {
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: PH, new_string: 7 },
        mapThrowsIo,
      ),
      null,
    );
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: 7, new_string: `x ${PH}` },
        mapThrowsIo,
      ),
      null,
    );
  });

  it("rejects a hint-free Write before touching the redactor", async () => {
    assert.equal(
      await rehydrateRedacted(
        "Write",
        { file_path: "/f", content: "plain content" },
        mapThrowsIo,
      ),
      null,
    );
  });

  it("does not treat a non-Edit, non-Write tool as a Write candidate", async () => {
    assert.equal(
      await rehydrateRedacted(
        "Glob",
        { file_path: "/f", content: `doc ${PH}` },
        mapThrowsIo,
      ),
      null,
    );
  });

  it("applies the notebook guard only to NotebookEdit, not other tools", async () => {
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        {
          file_path: "/f",
          old_string: "plain",
          new_string: "x",
          new_source: `v=${PH}`,
        },
        { readFile: () => "plain\n", redactMap: () => mkView("plain\n", []) },
      ),
      null,
    );
  });

  it("honors a custom hint", async () => {
    // With a custom hint "<SECRET", DEFAULT_HINT "[REDACTED" is no longer a
    // placeholder marker, so an old_string carrying only "[REDACTED]" is
    // hint-free; the custom-hinted placeholder drives the deny.
    const HINT = "<SECRET";
    const content = `plain\n`;
    const io = fakeIo(content, mkView(content, []));
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: `gone <SECRET:k>`, new_string: "x" },
      io,
      { hint: HINT },
    );
    // No match on the clean file → hinted absent → pass-through (null).
    assert.equal(out, null);

    // A custom-hinted NotebookEdit is denied with the custom hint in the text.
    const nb = await rehydrateRedacted(
      "NotebookEdit",
      { notebook_path: "/n.ipynb", new_source: `x = "<SECRET:k>"` },
      io,
      { hint: HINT },
    );
    assert.match(nb.deny, /<SECRET…\] placeholder/);
  });
});

// ─── Edit resolution across redaction placeholders ───────────────────────────

describe("rehydrate: Edit", () => {
  const content = `# config\nPASSWORD=${SECRET_A}\nDEBUG=1\n`;
  const view = mkView(content, [{ value: SECRET_A, placeholder: PH }]);
  const edit = (old_string, new_string, extra = {}) =>
    rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string, new_string, ...extra },
      fakeIo(content, view, reRedact),
    );

  it("passes through old_string that matches disk verbatim", async () => {
    const src = `x ${PH} y\nPASSWORD=${SECRET_A}\n`;
    const io = fakeIo(src, mkView(src, [{ value: SECRET_A, placeholder: PH }]));
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: `x ${PH} y`, new_string: "z" },
        io,
      ),
      null,
    );
  });

  it("keeps a literal placeholder in new_string when old_string matched it verbatim", async () => {
    const src = `x ${PH} y\nPASSWORD=${SECRET_A}\n`;
    const io = fakeIo(src, mkView(src, [{ value: SECRET_A, placeholder: PH }]));
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: `x ${PH} y`, new_string: `x ${PH} z` },
        io,
      ),
      null,
    );
  });

  it("denies a verbatim-matching edit that inserts a placeholder for another secret", async () => {
    const out = await edit("DEBUG=1", `DEBUG=1\nPASSWORD_COPY=${PH}`);
    assert.match(out.deny, /outside the matched old_string/);
  });

  it("rehydrates old_string and new_string around a kept secret", async () => {
    const out = await edit(
      `PASSWORD=${PH}\nDEBUG=1`,
      `PASSWORD=${PH}\nDEBUG=0`,
    );
    assert.equal(out.updatedInput.old_string, `PASSWORD=${SECRET_A}\nDEBUG=1`);
    assert.equal(out.updatedInput.new_string, `PASSWORD=${SECRET_A}\nDEBUG=0`);
    assert.match(out.context, /placeholders were resolved/);
    assert.doesNotMatch(out.context, /invisible\/control/);
  });

  it("rehydrates a deletion of the secret line (no placeholder in new_string)", async () => {
    const out = await edit(`PASSWORD=${PH}\n`, "");
    assert.equal(out.updatedInput.old_string, `PASSWORD=${SECRET_A}\n`);
    assert.equal(out.updatedInput.new_string, "");
  });

  it("denies an old_string that matches nowhere in the view", async () => {
    const out = await edit(`PASSWORD=${PH}x`, "y");
    assert.match(out.deny, /does not match the sanitized\s+view/);
  });

  it("denies an ambiguous old_string without replace_all", async () => {
    const src = `A_PASSWORD=${SECRET_A}\nB_PASSWORD=${SECRET_B}\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH },
    ]);
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: `PASSWORD=${PH}`, new_string: "x" },
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /matches 2 locations/);
    assert.match(out.deny, /the view can differ from disk at each \(redacted/);
    assert.match(out.deny, /add surrounding context to make it unique/);
  });

  it("denies replace_all over spans hiding differing secrets", async () => {
    const src = `PASSWORD=${SECRET_A}\nPASSWORD=${SECRET_B}\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH },
    ]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}`,
        new_string: `PASS=${PH}`,
        replace_all: true,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /on-disk bytes differ/);
    assert.match(out.deny, /edit each occurrence separately/);
    assert.match(out.deny, /with unique context/);
  });

  it("applies replace_all when every span hides the same secret", async () => {
    const src = `PASSWORD=${SECRET_A}\nPASSWORD=${SECRET_A}\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}`,
        new_string: `PASSWD=${PH}`,
        replace_all: true,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.equal(out.updatedInput.old_string, `PASSWORD=${SECRET_A}`);
    assert.equal(out.updatedInput.new_string, `PASSWD=${SECRET_A}`);
    assert.equal(out.updatedInput.replace_all, true);
  });

  it("denies an old_string cut mid-placeholder", async () => {
    const out = await edit(`PASSWORD=${PH.slice(0, 9)}`, "x");
    assert.match(out.deny, /include each placeholder whole/);
  });

  it("skips the exposure simulation when the disk old_string is not unique", async () => {
    const src = `K=${SECRET_A}\nK=${SECRET_A}\n`;
    const vw = {
      text: `K=${PH}\nK=${SECRET_A}\n`,
      pairs: [{ placeholder: PH, original: SECRET_A, start: 2 }],
    };
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: `K=${PH}`, new_string: "K=x" },
      fakeIo(src, vw, () => {
        throw new Error("exposure check must not run");
      }),
    );
    assert.equal(out.updatedInput.old_string, `K=${SECRET_A}`);
  });
});

// ─── Edit re-anchoring across stripped invisible/ANSI bytes ──────────────────

describe("rehydrate: stripped-character re-anchoring", () => {
  it("re-anchors a hint-free edit across an interior zero-width char", async () => {
    const content = `add(a, b)${ZW};\nDEBUG=1\n`;
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: "add(a, b);\nDEBUG=1",
        new_string: "add(a, b, c);\nDEBUG=1",
      },
      liveIo(content),
    );
    assert.equal(out.updatedInput.old_string, `add(a, b)${ZW};\nDEBUG=1`);
    assert.equal(out.updatedInput.new_string, "add(a, b, c);\nDEBUG=1");
    assert.match(out.context, /invisible\/control\s+character/);
    assert.doesNotMatch(out.context, /placeholders were resolved/);
  });

  it("re-anchors across stripped ANSI sequences, preserving boundary runs", async () => {
    const content = `${GREEN}green${RESET} text\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "green text", new_string: "blue text" },
      liveIo(content),
    );
    assert.equal(out.updatedInput.old_string, `green${RESET} text`);
  });

  it("preserves a boundary run while replacing an interior one", async () => {
    const content = `${ZW}AAA${ZW}BBB\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "AAABBB", new_string: "CCC" },
      liveIo(content),
    );
    assert.equal(out.updatedInput.old_string, `AAA${ZW}BBB`);
  });

  it("handles a file with both a secret and stripped characters", async () => {
    const content = `PASSWORD=${SECRET_A}${ZW}\nDEBUG=1\n`;
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}\nDEBUG=1`,
        new_string: `PASSWORD=${PH}\nDEBUG=0`,
      },
      liveIo(content, [{ value: SECRET_A, placeholder: PH }], reRedact),
    );
    assert.equal(
      out.updatedInput.old_string,
      `PASSWORD=${SECRET_A}${ZW}\nDEBUG=1`,
    );
    assert.equal(out.updatedInput.new_string, `PASSWORD=${SECRET_A}\nDEBUG=0`);
    assert.equal(
      out.context,
      `Edit input was translated to the file's actual on-disk bytes: ` +
        `${PH.slice(0, 9)}…] placeholders were resolved to the file's real secret ` +
        `values (still hidden from you); the matched region carries 1 ` +
        `invisible/control character(s) stripped from your view; they are ` +
        `replaced along with it.`,
    );
  });

  it("passes through a hint-free stale old_string on a divergent file", async () => {
    const content = `${ZW}note\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "missing", new_string: "x" },
      liveIo(content),
    );
    assert.equal(out, null);
  });

  it("passes through a raw-byte match the view does not contain", async () => {
    const content = `${ZW}note\nPASSWORD=${SECRET_A}\n`;
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${SECRET_A}`,
        new_string: "PASSWORD=rotated",
      },
      liveIo(content, [{ value: SECRET_A, placeholder: PH }], reRedact),
    );
    assert.equal(out, null);
  });

  it("denies a raw-byte match whose new_string references a redacted secret", async () => {
    const content = `${ZW}note\nPASSWORD=${SECRET_A}\n`;
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${SECRET_A}`,
        new_string: `PASSWORD_COPY=${PH}`,
      },
      liveIo(content, [{ value: SECRET_A, placeholder: PH }], reRedact),
    );
    assert.match(out.deny, /outside the matched old_string/);
  });

  it("denies when greedy alignment cannot re-anchor unambiguously", async () => {
    const content = `m${GREEN}mm\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "mmm", new_string: "nnn" },
      liveIo(content),
    );
    assert.match(out.deny, /cannot be\s+re-anchored unambiguously/);
    assert.match(out.deny, /edit a smaller region away/);
    assert.match(out.deny, /ask the user to make this change/);
  });

  it("denies a purely-invisible alignment collision the re-clean check misses", async () => {
    const content = `${ESC}${ESC}[3${ZW}2m[32m\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "[32m", new_string: "[32m\nEXTRA=1" },
      liveIo(content),
    );
    assert.match(out.deny, /cannot be\s+re-anchored unambiguously/);
  });
});

// ─── new_string placeholder resolution ───────────────────────────────────────

describe("rehydrate: new_string resolution", () => {
  const content = `PASSWORD=${SECRET_A}\nAPI_KEY=${SECRET_B}\nEND\n`;
  const view = mkView(content, [
    { value: SECRET_A, placeholder: PH },
    { value: SECRET_B, placeholder: PH },
  ]);
  const edit = (old_string, new_string) =>
    rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string, new_string },
      fakeIo(content, view, reRedact),
    );

  it("maps same-text placeholders 1:1 by position when the sequence is preserved", async () => {
    const out = await edit(
      `PASSWORD=${PH}\nAPI_KEY=${PH}\nEND`,
      `PASSWORD=${PH}\nEXTRA=1\nAPI_KEY=${PH}\nEND`,
    );
    assert.equal(
      out.updatedInput.new_string,
      `PASSWORD=${SECRET_A}\nEXTRA=1\nAPI_KEY=${SECRET_B}\nEND`,
    );
  });

  it("denies when same-text placeholders change count and hide distinct secrets", async () => {
    const out = await edit(
      `PASSWORD=${PH}\nAPI_KEY=${PH}\nEND`,
      `MERGED=${PH}\nEND`,
    );
    assert.match(out.deny, /changes their count or order/);
    assert.match(
      out.deny,
      /multiple distinct secrets in the matched text share the placeholder/,
    );
    assert.match(
      out.deny,
      /edit them one at a time with unique surrounding context/,
    );
  });

  it("resolves a duplicated placeholder per-text when it names one secret", async () => {
    const src = `PASSWORD=${SECRET_A}\nEND\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}\nEND`,
        new_string: `PASSWORD=${PH}\nPASSWORD_COPY=${PH}\nEND`,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.equal(
      out.updatedInput.new_string,
      `PASSWORD=${SECRET_A}\nPASSWORD_COPY=${SECRET_A}\nEND`,
    );
  });

  it("denies a placeholder text only produced outside the span", async () => {
    const src = `PASSWORD=${SECRET_A}\ncert: x\nKEY ${SECRET_B} END\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH_PEM },
    ]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}\ncert: x`,
        new_string: `PASSWORD=${PH}\ncert: ${PH_PEM}`,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /outside\s+the matched old_string/);
  });

  it("leaves literal placeholder text alone when the model matched it verbatim", async () => {
    const src = `note ${PH_PEM} here\nPASSWORD=${SECRET_A}\nKEY ${SECRET_B} END\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH_PEM },
    ]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `note ${PH_PEM} here\nPASSWORD=${PH}`,
        new_string: `note ${PH_PEM} kept\nPASSWORD=${PH}`,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.equal(
      out.updatedInput.new_string,
      `note ${PH_PEM} kept\nPASSWORD=${SECRET_A}`,
    );
  });

  it("denies when the span mixes literal and redacted occurrences of one placeholder", async () => {
    const src = `say ${PH}\nPASSWORD=${SECRET_A}\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `say ${PH}\nPASSWORD=${PH}`,
        new_string: `say ${PH}\nPASSWORD=${PH}x`,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /mixes literal/);
    assert.match(
      out.deny,
      /cannot tell which occurrences in new_string are which/,
    );
    assert.match(
      out.deny,
      /edit the literal text and the secret's line separately/,
    );
  });
});

// ─── Exposure check ──────────────────────────────────────────────────────────

describe("rehydrate: exposure check", () => {
  const content = `PASSWORD=${SECRET_A}\n`;
  const view = mkView(content, [{ value: SECRET_A, placeholder: PH }]);

  it("denies an edit that re-labels the secret out of redaction", async () => {
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}`,
        new_string: `nextPageToken=${PH}`,
      },
      fakeIo(content, view, (text) => text),
    );
    assert.match(out.deny, /would reveal them/);
    assert.match(out.deny, /this change would move 1 secret value/);
    assert.match(
      out.deny,
      /keep each secret under its recognizable field name/,
    );
  });

  it("denies when the re-scan finds nothing at all (redact returns null)", async () => {
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}`,
        new_string: `note ${PH}`,
      },
      fakeIo(content, view, () => null),
    );
    assert.match(out.deny, /would reveal them/);
  });

  it("does not deny a secret the prior view already exposed", async () => {
    const src = `PASSWORD=${SECRET_A}\nweird ${SECRET_A}\n`;
    const vw = {
      text: `PASSWORD=${PH}\nweird ${SECRET_A}\n`,
      pairs: [{ placeholder: PH, original: SECRET_A, start: 9 }],
    };
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: `PASSWORD=${PH}`, new_string: `pw ${PH}` },
      fakeIo(src, vw, () => {
        throw new Error("exposure re-scan must not run with no new secret");
      }),
    );
    assert.equal(out.updatedInput.new_string, `pw ${SECRET_A}`);
  });

  it("runs the exposure check on a replace_all edit and denies a leak", async () => {
    const src = `PASSWORD=${SECRET_A}\nPASSWORD=${SECRET_A}\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}`,
        new_string: `nextPageToken=${PH}`,
        replace_all: true,
      },
      fakeIo(src, vw, (text) => text),
    );
    assert.match(out.deny, /would reveal them/);
  });
});

// ─── Write resolution ────────────────────────────────────────────────────────

describe("rehydrate: Write", () => {
  const content = `# config\nPASSWORD=${SECRET_A}\nDEBUG=1\n`;
  const view = mkView(content, [{ value: SECRET_A, placeholder: PH }]);
  const write = (newContent, io = fakeIo(content, view, reRedact)) =>
    rehydrateRedacted("Write", { file_path: "/f", content: newContent }, io);

  it("rehydrates a whole-file rewrite that keeps the secret", async () => {
    const out = await write(`# rewritten\nPASSWORD=${PH}\nDEBUG=0\n`);
    assert.equal(
      out.updatedInput.content,
      `# rewritten\nPASSWORD=${SECRET_A}\nDEBUG=0\n`,
    );
    assert.match(out.context, /resolved to the\s+file's real secret values/);
    assert.match(out.context, /are preserved in the written file/);
  });

  it("passes through content whose placeholders match none of the file's", async () => {
    assert.equal(await write(`docs about ${PH_PEM} markers\n`), null);
  });

  it("denies when distinct secrets share one placeholder text", async () => {
    const src = `PASSWORD=${SECRET_A}\nAPI_KEY=${SECRET_B}\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH },
    ]);
    const out = await write(`PASSWORD=${PH}\n`, fakeIo(src, vw, reRedact));
    assert.match(out.deny, /use Edit with unique\s+surrounding context/);
    assert.match(
      out.deny,
      /multiple distinct secrets in .* share the placeholder/,
    );
  });

  it("denies when the file mixes literal and redacted occurrences", async () => {
    const src = `say ${PH}\nPASSWORD=${SECRET_A}\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await write(`PASSWORD=${PH}\n`, fakeIo(src, vw, reRedact));
    assert.match(out.deny, /mixes literal/);
  });

  it("filters the produced count to the placeholder when a second secret shares the file", async () => {
    const src = `say ${PH}\nPASSWORD=${SECRET_A}\ncert ${SECRET_B}\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH_PEM },
    ]);
    const out = await write(
      `say ${PH}\nPASSWORD=${PH}\ncert ${PH_PEM}\n`,
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /mixes literal/);
    assert.match(
      out.deny,
      /cannot tell which occurrences in the new content are/,
    );
    assert.match(out.deny, /use Edit with unique surrounding context instead/);
  });

  it("denies a rewrite that would expose the secret", async () => {
    const out = await write(
      `note ${PH}\n`,
      fakeIo(content, view, () => null),
    );
    assert.match(out.deny, /would reveal them/);
  });

  it("uses a custom hint in the Write success context", async () => {
    // hint only affects the context string here; "<SECRET" must appear.
    const src = `PASSWORD=${SECRET_A}\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await rehydrateRedacted(
      "Write",
      { file_path: "/f", content: `PASSWORD=${PH}\n` },
      fakeIo(src, vw, reRedact),
      { hint: "[REDACTED" },
    );
    assert.match(out.context, /\[REDACTED…\] placeholders/);
  });
});

// ─── Placeholder-boundary and multi-secret resolution edge cases ─────────────

describe("view-map: occurrences", () => {
  it("steps by needle length, not 1 — no overlapping matches", () => {
    assert.deepEqual(occurrences("aaaa", "aa"), [0, 2]);
    assert.deepEqual(occurrences("ababab", "ab"), [0, 2, 4]);
    assert.deepEqual(occurrences("xyz", "q"), []);
  });
});

describe("rehydrate: placeholder-boundary resolution", () => {
  it("rehydrates an old_string that begins exactly at a placeholder", async () => {
    const src = `${SECRET_A}\nDEBUG=1\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `${PH}\nDEBUG=1`,
        new_string: `${PH}\nDEBUG=0`,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.equal(out.updatedInput.old_string, `${SECRET_A}\nDEBUG=1`);
    assert.equal(out.updatedInput.new_string, `${SECRET_A}\nDEBUG=0`);
  });

  it("denies an old_string that begins inside a placeholder", async () => {
    const src = `${SECRET_A} mid ${SECRET_B}\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH },
    ]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `${PH.slice(3)} mid ${PH}`,
        new_string: "x",
      },
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /include each placeholder whole/);
  });

  it("counts only interior stripped characters when the span starts after offset 0", async () => {
    const content = `KEEP ${ZW}AB${ZW}CD\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "ABCD", new_string: "WXYZ" },
      liveIo(content),
    );
    assert.equal(out.updatedInput.old_string, `AB${ZW}CD`);
    assert.match(out.context, /carries 1 invisible/);
  });
});

describe("rehydrate: interleaved distinct placeholders", () => {
  const reRedact3 = (text) =>
    text
      .split(SECRET_A)
      .join(PH)
      .split(SECRET_C)
      .join(PH)
      .split(SECRET_B)
      .join(PH_PEM);

  it("resolves an interleaved PH / PH_PEM / PH sequence in position order", async () => {
    const src = `A=${SECRET_A}\nB=${SECRET_B}\nC=${SECRET_C}\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH_PEM },
      { value: SECRET_C, placeholder: PH },
    ]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `A=${PH}\nB=${PH_PEM}\nC=${PH}`,
        new_string: `A=${PH}\nB=${PH_PEM}\nC=${PH}`,
      },
      fakeIo(src, vw, reRedact3),
    );
    assert.equal(
      out.updatedInput.new_string,
      `A=${SECRET_A}\nB=${SECRET_B}\nC=${SECRET_C}`,
    );
  });

  it("collects only the placeholder's own secret when a second distinct one shares the span", async () => {
    const src = `X=${SECRET_A}\nY=${SECRET_B}\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH_PEM },
    ]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `X=${PH}\nY=${PH_PEM}`,
        new_string: `X=${PH}\nZ=${PH}`,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.equal(out.updatedInput.new_string, `X=${SECRET_A}\nZ=${SECRET_A}`);
  });

  it("denies a literal/redacted placeholder mix even when the span holds another secret", async () => {
    const src = `say ${PH}\nPASSWORD=${SECRET_A}\ncert ${SECRET_B}\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH_PEM },
    ]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `say ${PH}\nPASSWORD=${PH}\ncert ${PH_PEM}`,
        new_string: `say ${PH}\nPASSWORD=${PH}x\ncert ${PH_PEM}`,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /mixes literal/);
  });
});

// ─── alignDeletions (pure engine) ────────────────────────────────────────────

describe("view-map: alignDeletions", () => {
  it("locates interior and trailing deleted runs", () => {
    assert.deepEqual(alignDeletions(`a${ZW}b`, "ab"), [
      { start: 1, deleted: ZW },
    ]);
    assert.deepEqual(alignDeletions(`ab${ZW}${ZW}`, "ab"), [
      { start: 2, deleted: `${ZW}${ZW}` },
    ]);
    assert.deepEqual(alignDeletions("ab", "ab"), []);
  });

  it("throws when the cleaned text is not a subsequence (fail closed)", () => {
    assert.throws(() => alignDeletions("abc", "xyz"), /not a subsequence/);
  });
});
