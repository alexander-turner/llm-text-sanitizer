/**
 * Fast-check property tests for the HTML layer (Layers 2 & 3).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { unified } from "unified";
import rehypeParse from "rehype-parse";
import { visit, EXIT } from "unist-util-visit";

import {
  sanitizeHtml,
  isHiddenStyle,
  isHiddenElement,
  checkExfilUrl,
  COMMENT_PLACEHOLDER,
  HIDDEN_PLACEHOLDER,
} from "../src/html.mjs";
import { fcRunOptions } from "./test-helpers.mjs";

const runOptions = fcRunOptions({ numRuns: 500 });
const applyHtml = (text) => sanitizeHtml(text)?.text ?? text;
const checkProperty = (arbitrary, predicate) =>
  fc.assert(fc.property(arbitrary, predicate), runOptions);

// "Forbidden" = invisible on a rendered page: comments and hidden elements.
function containsForbiddenNode(htmlText) {
  const tree = unified().use(rehypeParse, { fragment: true }).parse(htmlText);
  let forbidden = false;
  visit(tree, (node) => {
    if (node.type !== "comment" && !isHiddenElement(node)) return undefined;
    forbidden = true;
    return EXIT;
  });
  return forbidden;
}

// ─── 1. Idempotence ──────────────────────────────────────────────────────────

const tagName = fc.constantFrom(
  "div",
  "span",
  "p",
  "script",
  "style",
  "a",
  "img",
  "iframe",
  "svg",
);
const safeAttrValue = fc
  .string({ maxLength: 30 })
  .map((raw) => raw.replace(/["<>&]/g, ""));
const attribute = fc
  .tuple(fc.constantFrom("style", "hidden", "src", "href", "id"), safeAttrValue)
  .map(([name, value]) => `${name}="${value}"`);
const htmlElement = fc
  .tuple(
    tagName,
    fc.array(attribute, { maxLength: 3 }),
    fc.string({ maxLength: 40 }),
  )
  .map(([name, attrs, inner]) => {
    const attrText = attrs.length === 0 ? "" : " " + attrs.join(" ");
    return `<${name}${attrText}>${inner}</${name}>`;
  });
const arbitraryHtmlFragment = fc
  .array(fc.oneof(fc.string({ maxLength: 60 }), htmlElement), { maxLength: 6 })
  .map((parts) => parts.join(" "));

describe("property: sanitizeHtml is idempotent", () => {
  it("second pass changes nothing", () =>
    checkProperty(arbitraryHtmlFragment, (input) => {
      const passOne = applyHtml(input);
      assert.equal(applyHtml(passOne), passOne);
    }));
});

// ─── 2. Hidden-style fuzz ────────────────────────────────────────────────────

const whitespace = fc.constantFrom("", " ", "\t", "\n ");
const importantFlag = fc.constantFrom(
  "",
  " !important",
  "!important",
  " ! Important",
);
const casedPropertyName = (lowercase) =>
  fc.constantFrom(
    lowercase,
    lowercase.toUpperCase(),
    lowercase[0].toUpperCase() + lowercase.slice(1),
  );
const zeroNumber = fc.constantFrom("0", "0.0", "0.00", "00", "0e0");
const zeroLength = fc
  .tuple(zeroNumber, fc.constantFrom("", "px", "em", "%", "pt", "rem"))
  .map(([number, unit]) => number + unit);
const offscreenLength = fc
  .tuple(
    fc.integer({ min: 901, max: 99999 }),
    fc.constantFrom("px", "em", "pt"),
  )
  .map(([number, unit]) => `-${number}${unit}`);
const unrelatedDecl = fc.constantFrom("", "; color: red", "; margin: 1px");
const wrapWithNoise = (declaration) =>
  fc
    .tuple(whitespace, declaration, importantFlag, whitespace, unrelatedDecl)
    .map(
      ([leading, decl, flag, trailing, extra]) =>
        leading + decl + flag + trailing + extra,
    );

const hidingDeclarations = {
  display: casedPropertyName("display").map((name) => `${name}: none`),
  visibility: casedPropertyName("visibility").map((name) => `${name}: hidden`),
  opacity: fc
    .tuple(casedPropertyName("opacity"), zeroNumber)
    .map(([name, number]) => `${name}: ${number}`),
  "offscreen-left": fc
    .tuple(
      casedPropertyName("position"),
      casedPropertyName("left"),
      offscreenLength,
    )
    .map(([pos, side, length]) => `${pos}: absolute; ${side}: ${length}`),
  "offscreen-top": fc
    .tuple(
      casedPropertyName("position"),
      casedPropertyName("top"),
      offscreenLength,
    )
    .map(([pos, side, length]) => `${pos}: fixed; ${side}: ${length}`),
  "clip-rect": casedPropertyName("position").map(
    (pos) => `${pos}: absolute; clip: rect(0,0,0,0)`,
  ),
  "text-indent": fc
    .tuple(casedPropertyName("text-indent"), offscreenLength)
    .map(([name, length]) => `${name}: ${length}`),
};
for (const dimension of ["height", "width", "font-size"]) {
  hidingDeclarations[dimension] = fc
    .tuple(casedPropertyName(dimension), zeroLength)
    .map(([name, length]) => `${name}: ${length}`);
}
for (const dimension of ["height", "max-width"]) {
  hidingDeclarations[`overflow+${dimension}`] = fc
    .tuple(
      casedPropertyName("overflow"),
      casedPropertyName(dimension),
      zeroLength,
    )
    .map(([overflow, dim, length]) => `${overflow}: hidden; ${dim}: ${length}`);
}

describe("property: hidden-style variants flagged by isHiddenStyle", () => {
  for (const [variantName, declaration] of Object.entries(hidingDeclarations)) {
    it(`flags ${variantName}`, () =>
      checkProperty(wrapWithNoise(declaration), (styleString) =>
        assert.equal(
          isHiddenStyle(styleString),
          true,
          `not flagged: ${JSON.stringify(styleString)}`,
        ),
      ));
  }
});

// Ordinary visible declarations a real page emits. isHiddenStyle splices the
// element's content out of the model's view, so flagging any of these would
// DELETE legitimate text — a curated allowlist pins that none ever reads as
// hidden, even wrapped in the same whitespace/!important/case noise the
// positive fuzz uses.
const visibleDeclaration = fc.constantFrom(
  "opacity: 0.15",
  "opacity: 0.5",
  "opacity: 1",
  "font-size: 11px",
  "font-size: 0.9em",
  "font-size: 14px",
  "transform: scale(0.8)",
  "transform: rotateY(45deg)",
  "transform: rotateY(89deg)",
  "transform: rotate(90deg)",
  "transform: translateX(-5px)",
  "position: absolute; left: -5px",
  "position: absolute; top: -1px",
  "position: absolute; left: -50vw",
  "position: absolute; left: -50%",
  "position: absolute; left: -10%",
  "position: absolute; left: calc(100% - 5px)",
  "margin-left: -2em",
  "text-indent: -0.5em",
  "clip-path: inset(10%)",
  "clip-path: circle(50%)",
  "color: white",
  "color: white; background: #fefefe",
  "color: #777; background: #888",
  "color: red",
);

describe("property: ordinary visible styles are never flagged hidden", () => {
  it("no curated visible declaration reads as hidden under noise", () =>
    checkProperty(wrapWithNoise(visibleDeclaration), (styleString) =>
      assert.equal(
        isHiddenStyle(styleString),
        false,
        `false positive: ${JSON.stringify(styleString)}`,
      ),
    ));
});

describe("property: isHiddenStyle never throws on arbitrary input", () => {
  it("returns a boolean for any string", () =>
    checkProperty(fc.string(), (styleString) => {
      assert.equal(typeof isHiddenStyle(styleString), "boolean");
    }));
  it("returns a boolean for plausibly-CSS strings", () => {
    const cssLike = fc
      .array(
        fc
          .tuple(
            fc.constantFrom(
              "color",
              "opacity",
              "transform",
              "clip-path",
              "left",
              "font-size",
              "background",
              "visibility",
            ),
            fc.string({ maxLength: 20 }),
          )
          .map(([prop, value]) => `${prop}:${value}`),
        { maxLength: 5 },
      )
      .map((decls) => decls.join(";"));
    checkProperty(cssLike, (styleString) => {
      assert.equal(typeof isHiddenStyle(styleString), "boolean");
    });
  });
});

// ─── 3. URL exfil monotonicity ───────────────────────────────────────────────

const base64Char = fc.constantFrom(
  ..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".split(
    "",
  ),
);
const arbitraryFlaggableSegment = fc
  .array(base64Char, { minLength: 48, maxLength: 96 })
  .map((chars) => chars.join(""));
const arbitraryPayloadSegment = fc
  .array(base64Char, { minLength: 0, maxLength: 80 })
  .map((chars) => chars.join(""));
const arbitraryBaseUrl = fc.constantFrom(
  "https://x.com/p",
  "/log",
  "http://a/b/c",
);
const arbitraryParamName = fc.constantFrom("q", "data", "token", "x");

describe("property: checkExfilUrl monotonic in payload length", () => {
  it("appending bytes never un-flags", () => {
    let sawFlagged = 0;
    fc.assert(
      fc.property(
        arbitraryBaseUrl,
        arbitraryParamName,
        arbitraryFlaggableSegment,
        arbitraryPayloadSegment,
        (baseUrl, paramName, headSegment, extraSegment) => {
          const shortUrl = `${baseUrl}?${paramName}=${headSegment}`;
          const longUrl = `${baseUrl}?${paramName}=${headSegment}${extraSegment}`;
          const shortFlagged = checkExfilUrl(shortUrl) !== null;
          const longFlagged = checkExfilUrl(longUrl) !== null;
          if (shortFlagged) sawFlagged += 1;
          assert.ok(
            !shortFlagged || longFlagged,
            `mono violated: ${shortUrl} flagged but ${longUrl} not`,
          );
        },
      ),
      runOptions,
    );
    assert.ok(
      sawFlagged > 0,
      "no short URL was ever flagged — property vacuous",
    );
  });
});

// ─── 4. Round-trip: no forbidden node survives ──────────────────────────────

const adversarialStyle = fc.constantFrom(
  "display:none",
  "visibility:hidden",
  "opacity:0",
  "position:absolute;left:-9999px",
  "position:fixed;top:-10000px",
  "clip:rect(0,0,0,0);position:absolute",
  "text-indent:-9999px",
  "height:0",
  "overflow:hidden;max-width:0",
  "font-size:0",
);
const adversarialNode = fc.oneof(
  fc.constant("<!-- secret -->"),
  fc.constant("<div hidden>x</div>"),
  adversarialStyle.map((style) => `<div style="${style}">h</div>`),
  adversarialStyle.map((style) => `<span style='${style}'>x</span>`),
);
const benignNode = fc.constantFrom(
  "hello",
  "<p>v</p>",
  "<b>b</b>",
  "<script>alert(1)</script>",
  "",
  "\n",
);
const arbitraryAdversarialDoc = fc
  .array(fc.oneof(benignNode, adversarialNode), { minLength: 1, maxLength: 8 })
  .map((parts) => parts.join("\n"));

describe("property: sanitizeHtml round-trip drops all forbidden nodes", () => {
  it("comment/hidden never survives (script is preserved by design)", () =>
    checkProperty(arbitraryAdversarialDoc, (input) => {
      const sanitized = applyHtml(input);
      assert.equal(
        containsForbiddenNode(sanitized),
        false,
        `survived: ${JSON.stringify(sanitized)}`,
      );
    }));
});

// ─── 5. Splice fidelity ──────────────────────────────────────────────────────

const proseChunk = fc.stringMatching(/^[a-zA-Z0-9 .,'!?_*|-]{1,40}$/);
const prosePrefix = fc.stringMatching(
  /^[a-zA-Z0-9.,'!?_*|-][a-zA-Z0-9 .,'!?_*|-]{0,39}$/,
);

describe("property: splice fidelity", () => {
  it("a stripped comment leaves surrounding bytes byte-identical", () =>
    checkProperty(fc.tuple(prosePrefix, proseChunk), ([prefix, suffix]) =>
      assert.equal(
        applyHtml(`${prefix}<!-- secret -->${suffix}`),
        `${prefix}${COMMENT_PLACEHOLDER}${suffix}`,
      ),
    ));
  it("a stripped hidden span leaves surrounding bytes byte-identical", () =>
    checkProperty(fc.tuple(prosePrefix, proseChunk), ([prefix, suffix]) =>
      assert.equal(
        applyHtml(`${prefix}<span style="display:none">x</span>${suffix}`),
        `${prefix}${HIDDEN_PLACEHOLDER}${suffix}`,
      ),
    ));
  it("a reported script does not modify the text at all", () =>
    checkProperty(fc.tuple(prosePrefix, proseChunk), ([prefix, suffix]) => {
      const input = `${prefix}<script>x</script>${suffix}`;
      const result = sanitizeHtml(input);
      assert.equal(result.text, input);
      assert.equal(result.warned.tags.script, 1);
    }));
});
