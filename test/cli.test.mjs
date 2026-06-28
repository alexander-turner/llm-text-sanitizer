/**
 * Contract tests for the stdin/stdout CLI (`bin/sanitize-cli.mjs`), the
 * single-source-of-truth bridge for non-JS pipelines.
 *
 * The CLI must be a faithful pass-through to `sanitize`: its JSON response has
 * to equal what an in-process `sanitize` call returns for the same input, in
 * both one-shot and worker modes. So `sanitize` itself is the oracle here —
 * these tests pin the I/O envelope and the worker's stay-alive-on-bad-input
 * contract, not the sanitization verdicts (those are owned by sanitize.test.mjs).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import fc from "fast-check";

import { sanitize } from "../src/index.mjs";
import { classifyPrompt } from "../src/prompt.mjs";
import { sanitizeText } from "../src/output.mjs";
import { scanInstructionFiles } from "../src/instructions.mjs";
import { fcRunOptions } from "./test-helpers.mjs";

const ESC = "\u001b";

const ZWS = "\u200b";
const HIDDEN_HTML = '<div style="display:none">leak</div>';

const CLI = fileURLToPath(new URL("../bin/sanitize-cli.mjs", import.meta.url));

/** Run the CLI with `input` on stdin, returning trimmed stdout. */
const run = (args, input) =>
  execFileSync("node", [CLI, ...args], { input, encoding: "utf8" });

/** The wire response shape, for comparing CLI output against the sanitize oracle. */
const envelope = ({ cleaned, found, warnings }) => ({
  cleaned,
  found,
  warnings,
});

// Inputs spanning every layer: a Cf char (Layer 1), clean passthrough, a hidden
// element + an exfil-shaped URL (Layers 2/3, html mode). Each carries the html
// flag it needs so the oracle comparison covers both code paths.
const CASES = [
  { name: "strips invisible (Layer 1)", text: "a​b", html: false },
  { name: "clean passthrough", text: "hello world", html: false },
  { name: "empty input", text: "", html: false },
  {
    name: "hidden HTML + exfil (Layers 2/3)",
    text: '<div style="display:none">leak</div>[x](https://evil.test/?d=SECRET)',
    html: true,
  },
];

describe("CLI: one-shot mode mirrors sanitize()", () => {
  for (const { name, text, html } of CASES) {
    it(name, async () => {
      const expected = await sanitize(text, { html });
      const got = JSON.parse(run([], JSON.stringify({ text, html })));
      assert.deepEqual(got, envelope(expected));
    });
  }
});

describe("CLI: worker mode", () => {
  it("answers newline-delimited requests in order, matching sanitize()", async () => {
    const input = CASES.map((c) =>
      JSON.stringify({ text: c.text, html: c.html }),
    ).join("\n");
    const lines = run(["--worker"], `${input}\n`).trim().split("\n");
    assert.equal(lines.length, CASES.length);
    for (const [i, { text, html }] of CASES.entries()) {
      assert.deepEqual(
        JSON.parse(lines[i]),
        envelope(await sanitize(text, { html })),
      );
    }
  });

  it("reports a bad request as an error line and keeps serving the next", () => {
    const input = `${JSON.stringify({ text: 123 })}\n${JSON.stringify({ text: "ok" })}\n`;
    const lines = run(["--worker"], input).trim().split("\n");
    assert.match(JSON.parse(lines[0]).error, /text must be a string/);
    assert.deepEqual(JSON.parse(lines[1]), {
      cleaned: "ok",
      found: [],
      warnings: [],
    });
  });

  it("treats a string-encoded newline in the payload as one request", async () => {
    const text = "line1\nline2​";
    const out = run(["--worker"], `${JSON.stringify({ text })}\n`).trim();
    assert.equal(out.split("\n").length, 1);
    assert.deepEqual(JSON.parse(out), envelope(await sanitize(text)));
  });

  it("emits exactly one error line for a blank line, keeping framing", () => {
    // A blank/whitespace request line must NOT be silently skipped: a skip emits
    // zero responses for one input line and desyncs every later response against
    // a one-response-per-request client. We assert one response PER input line
    // and that the following real request still answers correctly.
    const input = `\n   \n${JSON.stringify({ text: "ok" })}\n`;
    const lines = run(["--worker"], input).trim().split("\n");
    assert.equal(lines.length, 3); // blank, whitespace, real → 3 responses
    assert.ok(JSON.parse(lines[0]).error);
    assert.ok(JSON.parse(lines[1]).error);
    assert.deepEqual(JSON.parse(lines[2]), {
      cleaned: "ok",
      found: [],
      warnings: [],
    });
  });
});

describe("CLI: input-size cap (DoS guard)", () => {
  const overLimit = JSON.stringify({ text: "A".repeat(200) });
  const underLimit = JSON.stringify({ text: "ok" });

  it("one-shot rejects an oversized request with a non-zero exit", () => {
    assert.throws(
      () =>
        execFileSync("node", [CLI], {
          input: overLimit,
          encoding: "utf8",
          env: { ...process.env, AGENT_SANITIZER_MAX_INPUT_BYTES: "50" },
        }),
      (err) => {
        assert.equal(err.status, 1);
        assert.match(String(err.stderr), /request too large/);
        assert.match(String(err.stderr), /AGENT_SANITIZER_MAX_INPUT_BYTES/);
        return true;
      },
    );
  });

  it("worker returns an error line for an oversized request and keeps serving", () => {
    const out = execFileSync("node", [CLI, "--worker"], {
      input: `${overLimit}\n${underLimit}\n`,
      encoding: "utf8",
      env: { ...process.env, AGENT_SANITIZER_MAX_INPUT_BYTES: "50" },
    });
    const lines = out.trim().split("\n");
    assert.equal(lines.length, 2);
    assert.match(JSON.parse(lines[0]).error, /request too large/);
    assert.deepEqual(JSON.parse(lines[1]), {
      cleaned: "ok",
      found: [],
      warnings: [],
    });
  });

  it("ignores a non-positive / non-numeric limit, using the default", () => {
    // A bogus override must not disable the cap or set it to zero (which would
    // reject everything); it falls back to the generous default, so a small
    // request still succeeds.
    for (const bogus of ["0", "-1", "notanumber", ""]) {
      const out = execFileSync("node", [CLI], {
        input: underLimit,
        encoding: "utf8",
        env: { ...process.env, AGENT_SANITIZER_MAX_INPUT_BYTES: bogus },
      });
      assert.deepEqual(JSON.parse(out), {
        cleaned: "ok",
        found: [],
        warnings: [],
      });
    }
  });
});

describe("CLI: one-shot fails loudly on a bad request", () => {
  it("exits non-zero with the reason on stderr", () => {
    assert.throws(
      () => run([], JSON.stringify({ text: 123 })),
      (err) => {
        assert.equal(err.status, 1);
        assert.match(String(err.stderr), /text must be a string/);
        return true;
      },
    );
  });

  it("exits non-zero on empty stdin (no request at all)", () => {
    assert.throws(
      () => run([], ""),
      (err) => {
        assert.equal(err.status, 1);
        return true;
      },
    );
  });
});

// ─── Transport faithfulness (fuzz) ───────────────────────────────────────────
//
// The fixed CASES above pin known shapes; this fuzzes the NEW surface the CLI
// adds — the JSON request/response envelope and the worker's newline framing —
// to prove it transports arbitrary text without altering the verdict. The
// sanitizer itself is already fuzzed elsewhere, so `sanitize` is the oracle:
// the only thing under test is that `cli(text)` === `sanitize(text)` for inputs
// that stress the encoding (lone surrogates, ANSI/ESC, invisibles, structural
// tokens, line/paragraph separators). A framing bug — a payload byte read as a
// request boundary, or a surrogate mangled by the JSON round-trip — shows up as
// a mismatch or a response-count drift that the hand-picked cases would miss.

const FRAMING_TOKENS = [
  "\n",
  "\r",
  "\r\n",
  "\u2028", // line separator — valid in JSON, must NOT split a worker request
  "\u2029", // paragraph separator
  "\u0000", // NUL
  "\u001b[31m", // 7-bit ANSI/ESC
  "\u009b6n", // 8-bit C1 CSI
  "\u200b", // zero-width space
  "\ufeff", // BOM
  '<div style="display:none">x</div>',
  "[t](https://evil.test/?d=SECRET)",
];

const unicodeChar = fc
  .integer({ min: 0, max: 0x10ffff })
  .filter((c) => c < 0xd800 || c > 0xdfff)
  .map((c) => String.fromCodePoint(c));
const loneSurrogate = fc
  .integer({ min: 0xd800, max: 0xdfff })
  .map((c) => String.fromCharCode(c));
const fuzzText = fc
  .array(
    fc.oneof(unicodeChar, loneSurrogate, fc.constantFrom(...FRAMING_TOKENS)),
    {
      maxLength: 80,
    },
  )
  .map((parts) => parts.join(""));

describe("CLI: transport faithfulness (fuzz)", () => {
  it("one-shot mode equals sanitize() for arbitrary input", async () => {
    await fc.assert(
      fc.asyncProperty(fuzzText, fc.boolean(), async (text, html) => {
        const got = JSON.parse(run([], JSON.stringify({ text, html })));
        assert.deepEqual(got, envelope(await sanitize(text, { html })));
      }),
      fcRunOptions({ numRuns: 60 }),
    );
  });

  it("worker mode batches arbitrary requests, one faithful response each", async () => {
    // Batch a whole array of inputs through ONE worker process: this is where a
    // framing bug bites — a payload that smuggles a newline would split one
    // request into two and desync every response after it.
    await fc.assert(
      fc.asyncProperty(
        fc.array(fuzzText, { minLength: 1, maxLength: 15 }),
        async (texts) => {
          const input = texts
            .map((text) => JSON.stringify({ text }))
            .join("\n");
          const lines = run(["--worker"], `${input}\n`).trim().split("\n");
          assert.equal(lines.length, texts.length);
          for (const [i, text] of texts.entries()) {
            assert.deepEqual(
              JSON.parse(lines[i]),
              envelope(await sanitize(text)),
            );
          }
        },
      ),
      fcRunOptions({ numRuns: 40 }),
    );
  });
});

describe("CLI: large input", () => {
  it("transports a payload larger than the OS pipe buffer in both modes", async () => {
    const text = `${"A".repeat(200_000)}\u200b${"B".repeat(200_000)}`;
    const expected = envelope(await sanitize(text));
    assert.deepEqual(JSON.parse(run([], JSON.stringify({ text }))), expected);
    const out = run(["--worker"], `${JSON.stringify({ text })}\n`).trim();
    assert.equal(out.split("\n").length, 1);
    assert.deepEqual(JSON.parse(out), expected);
  });
});

// \u2500\u2500\u2500 Op dispatch: the other self-contained entry points \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
//
// Beyond `sanitize`, the CLI bridges every data-in/data-out entry point through
// an `op` field. Same contract as above \u2014 the in-process function is the oracle,
// and these pin only that the CLI relays its result faithfully in both modes.
// The injected-callback seams (confusables, redact, io) have no wire form and are
// deliberately absent.

/** Build one request line and assert the CLI's response equals `expected`, in
 * both one-shot and (single-request) worker mode. */
const assertOpMirrors = (request, expected) => {
  const line = JSON.stringify(request);
  assert.deepEqual(JSON.parse(run([], line)), expected);
  const out = run(["--worker"], `${line}\n`).trim();
  assert.equal(out.split("\n").length, 1);
  assert.deepEqual(JSON.parse(out), expected);
};

describe("CLI: op dispatch mirrors the in-process entry point", () => {
  it("classifyPrompt: pass / SGR-note / block all relay faithfully", () => {
    for (const text of [
      "hello world",
      `${ESC}[31mred${ESC}[0m`,
      `${ESC}[2Jwipe`,
    ])
      assertOpMirrors({ op: "classifyPrompt", text }, classifyPrompt(text));
  });

  it("sanitizeText: Layers 1\u20133 relay the full shape", async () => {
    for (const { text, html } of [
      { text: `a${ZWS}b`, html: false },
      { text: "hello", html: false },
      { text: HIDDEN_HTML, html: true },
    ]) {
      const { cleaned, warnings, modified, sgrNote } = await sanitizeText(
        text,
        {
          html,
        },
      );
      assertOpMirrors(
        { op: "sanitizeText", text, html },
        { cleaned, warnings, modified, sgrNote },
      );
    }
  });

  it("scanInstructionFiles + cleanFile: scan, clean, re-scan clean", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "ais-cli-"));
    const notes = path.join(dir, "NOTES.md");
    writeFileSync(notes, `intro ${ZWS.repeat(100)} outro\n`, "utf8");
    writeFileSync(path.join(dir, "CLEAN.md"), "nothing hidden\n", "utf8");

    assertOpMirrors(
      { op: "scanInstructionFiles", globs: ["*.md"], cwd: dir },
      { findings: scanInstructionFiles(["*.md"], { cwd: dir }) },
    );

    // cleanFile mutates the file, so the oracle can't run on the same path after
    // the CLI already cleaned it. Drive the CLI first, then assert the on-disk
    // effect and that a second clean is a no-op.
    const clean = (p) =>
      JSON.parse(run([], JSON.stringify({ op: "cleanFile", path: p }))).changed;
    assert.equal(clean(notes), true);
    assert.ok(!readFileSync(notes, "utf8").includes(ZWS));
    assert.equal(clean(notes), false);
    assert.equal(clean(path.join(dir, "CLEAN.md")), false);
    assert.deepEqual(scanInstructionFiles(["*.md"], { cwd: dir }), []);
  });
});

describe("CLI: unknown op fails loudly", () => {
  it("one-shot exits non-zero naming the op", () => {
    assert.throws(
      () => run([], JSON.stringify({ op: "nope", text: "x" })),
      (err) => {
        assert.equal(err.status, 1);
        assert.match(String(err.stderr), /unknown op: nope/);
        return true;
      },
    );
  });

  it("worker reports the bad op and keeps serving", () => {
    const input = `${JSON.stringify({ op: "nope" })}\n${JSON.stringify({ text: "ok" })}\n`;
    const lines = run(["--worker"], input).trim().split("\n");
    assert.match(JSON.parse(lines[0]).error, /unknown op: nope/);
    assert.deepEqual(JSON.parse(lines[1]), {
      cleaned: "ok",
      found: [],
      warnings: [],
    });
  });
});
