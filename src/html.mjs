/**
 * Hidden-HTML splicing (Layer 2) and exfil-URL detection (Layer 3) for
 * web/HTML ingress.
 *
 * Layer 2 strips exactly what a human viewing the rendered page cannot see —
 * HTML comments and hidden elements (hiding inline styles, `hidden` attr) —
 * by splicing those byte ranges out of the original text and leaving a
 * placeholder; every byte outside a spliced range is preserved verbatim (no
 * re-serialization). Scripting/resource tags (script, style, svg, iframe, …)
 * and `data:` URI resources are REPORTED in the result's `warned` counts but
 * never removed, so fetched page source stays inspectable.
 *
 * Layer 3 reports data-exfil-shaped URLs (suspicious query params, oversized
 * payloads, embedded credentials) without modifying them; the caller surfaces
 * the report as a warning.
 *
 * Split into its own module so it can be lazy-loaded: pulling in the
 * remark/rehype/unified graph costs ~200ms of module-load time, so the main
 * entry `await import()`s this module only when its cheap regex gates match.
 */
import { unified } from "unified";
import remarkParse from "remark-parse";
import remarkGfm from "remark-gfm";
import rehypeParse from "rehype-parse";
import { visit, SKIP, EXIT } from "unist-util-visit";
import styleToObject from "style-to-object";
import {
  HTML_TAG_PRESENT,
  MD_LINK_HINT,
  SECRET_HINT,
  SECRET_HINT_EXT,
  matchesSecretHint,
} from "./gates.mjs";

// The cheap pre-gates live in the dependency-free `./gates.mjs` so the package
// root can re-export them without eagerly loading this module's remark/rehype
// graph. Re-exported here too so the `./html` subpath keeps exposing them.
export {
  HTML_TAG_PRESENT,
  MD_LINK_HINT,
  SECRET_HINT,
  SECRET_HINT_EXT,
  matchesSecretHint,
};

// ─── Layer 2: hidden-content detection ───────────────────────────────────────

// A length/opacity/size is "near zero" when its magnitude is below this — a
// browser renders 0.0001px text or 0.001 opacity as effectively invisible, so
// requiring an exact 0 lets a trivially-perturbed value slip through.
const NEAR_ZERO_EPSILON = 0.01;

/** @param {string} value @returns {boolean} */
function isNearZeroLength(value) {
  if (!value) return false;
  const number = parseFloat(value);
  return Number.isFinite(number) && Math.abs(number) < NEAR_ZERO_EPSILON;
}

// A negative offset is "offscreen" only when it pushes the element ENTIRELY
// past the viewport edge — the magnitude that takes depends on the unit. An
// absolute unit (px and the font/char units) needs a large magnitude
// (< -900px). A viewport/percent unit clears the screen only at a full
// viewport-width: -100vw / -100% push a normal-width element fully out, but
// -50vw / -50% leave roughly half of it on screen, so the threshold is a full
// -100, not a partial shift. Flagging a partial shift would splice visible
// text, so this errs toward false-negative.
const OFFSCREEN_ABSOLUTE_THRESHOLD = -900;
const OFFSCREEN_VIEWPORT_THRESHOLD = -100;
// The numeric arm accepts a sign and scientific notation (`-1e4px`) so a
// browser-honored exponent form is read at its true magnitude, not truncated
// at the `e` (which would make `translateX(-1e4px)` read as `-1px`, on-screen).
const ABSOLUTE_UNIT_RE =
  /^[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?\s*(?:px|em|rem|ex|ch|pt|pc|in|cm|mm)?$/;
const VIEWPORT_UNIT_RE =
  /^[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?\s*(?:vw|vh|vmin|vmax|%)$/;

/** @param {string} value @returns {boolean} */
function isOffscreenOffset(value) {
  if (!value) return false;
  if (ABSOLUTE_UNIT_RE.test(value))
    return parseFloat(value) < OFFSCREEN_ABSOLUTE_THRESHOLD;
  if (VIEWPORT_UNIT_RE.test(value))
    return parseFloat(value) <= OFFSCREEN_VIEWPORT_THRESHOLD;
  // `calc(...)` is deliberately NOT treated as offscreen. Resolving a calc
  // needs the layout context (`calc(100% - 5px)` is an ordinary in-flow
  // position), and a unit-blind "contains a negative number" guess flags those
  // benign expressions — which would splice visible text. Ambiguity must fail
  // OPEN (visible), so unresolved calc is left alone.
  return false;
}

/**
 * A `transform` that renders text invisible: scaled to (near) nothing, rotated
 * edge-on (a quarter turn around X or Y leaves a zero-area projection), or
 * translated far off any viewport.
 * @param {string} transform
 * @returns {boolean}
 */
function isHidingTransform(transform) {
  if (!transform) return false;
  // scale()/matrix() with a (near-)zero factor. The numeric capture accepts a
  // leading sign and scientific notation (`1e-3`, `-1E-4`); without the
  // exponent arm `scale(1e-3)` would capture only `1` and read as visible.
  const scale = transform.match(
    /\b(?:scale|scale3d|scalex|scaley|matrix|matrix3d)\(\s*([-+]?\d*\.?\d+(?:[eE][-+]?\d+)?)/,
  );
  if (scale && Math.abs(parseFloat(scale[1])) < NEAR_ZERO_EPSILON) return true;
  // rotateX/rotateY by an odd multiple of 90deg turns the box edge-on (zero
  // projected area). Only the axis-specific rotations collapse to a line; a
  // plain rotate()/rotateZ() spins in-plane and stays visible.
  const rotate = transform.match(/\brotate[xy]\(\s*(-?\d*\.?\d+)deg/i);
  if (rotate) {
    const degrees = ((parseFloat(rotate[1]) % 360) + 360) % 360;
    if (degrees === 90 || degrees === 270) return true;
  }
  // translateX/translateY/translate far off-screen. A two-axis `translate(x, y)`
  // hides when EITHER axis clears the viewport, so split the argument list and
  // test each — checking only the first arg missed a `translate(0, -9999px)`.
  for (const match of transform.matchAll(/\btranslate(?:[xy])?\(\s*([^)]*)/gi))
    for (const arg of match[1].split(","))
      if (isOffscreenOffset(arg.trim())) return true;
  return false;
}

/**
 * A `filter` that renders content invisible: an `opacity(0)` function drops the
 * element to fully transparent. The amount is a <number-percentage> (`0`..`1` or
 * `0%`..`100%`), so a percentage is divided to a fraction before the near-zero
 * test. Other filter functions (blur, brightness, drop-shadow) keep content
 * visible and are left alone; an unparseable amount fails OPEN (visible).
 * @param {string} filter
 * @returns {boolean}
 */
function isHidingFilter(filter) {
  if (!filter) return false;
  const match = filter.match(/\bopacity\(\s*([0-9]*\.?[0-9]+)\s*(%?)\s*\)/i);
  if (!match) return false;
  const value = parseFloat(match[1]);
  const fraction = match[2] === "%" ? value / 100 : value;
  return fraction < NEAR_ZERO_EPSILON;
}

/** @param {(key: string) => string} val */
function isPositionedOffscreen(val) {
  if (!/\babsolute\b|\bfixed\b/.test(val("position"))) return false;
  for (const side of ["left", "top", "right", "bottom"])
    if (isOffscreenOffset(val(side))) return true;
  const clip = val("clip");
  return Boolean(clip && /rect\s*\(\s*0/.test(clip));
}

// CSS named colors that participate in a white-on-white / black-on-black style
// of hiding. The full named-color set is unnecessary — only colors that
// commonly back hidden text need a canonical form for the equality compare.
/** @type {Record<string, string>} */
const NAMED_COLORS = {
  white: "#ffffff",
  black: "#000000",
  red: "#ff0000",
  transparent: "transparent",
};

/**
 * True when a canonicalized color is a concrete value we can compare for
 * equality — a resolved `#rrggbb` hex or `transparent`. `var(--x)`/`inherit`/
 * `currentColor` canonicalize to their raw token and are NOT concrete: their
 * effective color depends on the cascade, so a same-color hide can't be proven.
 * @param {string} canonical
 * @returns {boolean}
 */
function isConcreteColor(canonical) {
  return canonical === "transparent" || /^#[0-9a-f]{6}$/.test(canonical);
}

/**
 * Canonicalize a CSS color to lowercase `#rrggbb` so `white`, `#FFF`,
 * `#ffffff`, and `rgb(255, 255, 255)` all compare equal. Returns the trimmed
 * lowercased input unchanged when it is not a form we recognize; callers gate
 * the same-color compare on isConcreteColor so an unresolved token (`var()`,
 * `inherit`) never falsely reads as a same-color hide.
 * @param {string} raw
 * @returns {string}
 */
function canonicalizeColor(raw) {
  const value = raw.trim().toLowerCase();
  if (!value) return "";
  // Own-key only: `in` would match inherited members, so a CSS value of
  // `__proto__`/`constructor`/`toString` returns an object or function here
  // (poisoning isHiddenStyle's return) instead of falling through as a plain
  // string.
  if (Object.hasOwn(NAMED_COLORS, value)) return NAMED_COLORS[value];
  const shortHex = value.match(/^#([0-9a-f])([0-9a-f])([0-9a-f])$/);
  if (shortHex)
    return `#${shortHex[1]}${shortHex[1]}${shortHex[2]}${shortHex[2]}${shortHex[3]}${shortHex[3]}`;
  if (/^#[0-9a-f]{6}$/.test(value)) return value;
  const rgb = value.match(
    /^rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*(?:,[^)]*)?\)$/,
  );
  if (rgb) {
    /** @param {string} n */
    const hex = (n) => Number(n).toString(16).padStart(2, "0");
    return `#${hex(rgb[1])}${hex(rgb[2])}${hex(rgb[3])}`;
  }
  return value;
}

// The leading color token of a `background` shorthand (the first token that
// canonicalizes to a real color), so `background:#fff url(x)` still compares.
/** @param {string} shorthand @returns {string} */
function backgroundColor(shorthand) {
  for (const token of shorthand.split(/\s+/)) {
    const color = canonicalizeColor(token);
    if (color && (color.startsWith("#") || color === "transparent"))
      return color;
  }
  return "";
}

/** @param {(key: string) => string} val */
function isOverflowHidden(val) {
  if (val("overflow") !== "hidden") return false;
  for (const dim of ["height", "width", "max-height", "max-width"]) {
    const value = val(dim);
    if (value && parseFloat(value) === 0) return true;
  }
  return false;
}

/**
 * @param {string} styleStr
 * @returns {boolean}
 */
export function isHiddenStyle(styleStr) {
  // style-to-object throws on syntactically invalid CSS; a browser would
  // ignore the broken declaration, so we do too rather than letting the
  // exception escape and suppress the entire tool output.
  let rawProps;
  try {
    // @ts-ignore -- style-to-object default export not resolved under NodeNext
    rawProps = styleToObject(styleStr);
  } catch {
    return false;
  }
  if (!rawProps) return false;

  // CSS property names are case-insensitive and `!important` is a legal
  // trailing flag; style-to-object preserves both verbatim.
  /** @type {Record<string, string>} */
  const props = {};
  for (const [key, value] of Object.entries(rawProps)) {
    props[key.toLowerCase()] = String(value).replace(
      // Bounded whitespace runs: `\s*` on both sides of an unanchored match
      // backtracks super-linearly (redos/no-vulnerable). A CSS value never
      // carries more than a couple of spaces around `!important`.
      /\s{0,8}!\s{0,8}important\s{0,8}$/i,
      "",
    );
  }

  /** @param {string} key */
  const val = (key) => (props[key] || "").toString().trim().toLowerCase();

  if (val("display") === "none") return true;
  if (val("visibility") === "hidden" || val("visibility") === "collapse")
    return true;
  // `content-visibility:hidden` skips rendering the element's contents entirely
  // (not even laid out), so the text is invisible to a human but present in the
  // source. `auto`/`visible` keep it rendered and must not match.
  if (val("content-visibility") === "hidden") return true;

  // CSS clamps opacity to [0,1], so any NEGATIVE value renders fully
  // transparent — `< EPSILON` (no `Math.abs`) treats `-1`/`-0.5` as hidden,
  // where the old `Math.abs` mapped `-1` to `1` (visible) and let a
  // negative-opacity hide slip through. `opacity` is a <number> or <percentage>;
  // a value with any other unit (`0px`) is an INVALID declaration a browser
  // ignores (element stays visible), so fail open on anything that isn't a bare
  // number or percentage rather than `parseFloat`-ing the leading `0` out of it.
  const opacity = val("opacity");
  const opacityMatch = opacity.match(
    /^([+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)(%?)$/,
  );
  if (opacityMatch) {
    const n = parseFloat(opacityMatch[1]) / (opacityMatch[2] ? 100 : 1);
    if (n < NEAR_ZERO_EPSILON) return true;
  }

  for (const dim of ["height", "width", "font-size"])
    if (isNearZeroLength(val(dim))) return true;

  if (isPositionedOffscreen(val)) return true;

  if (isOffscreenOffset(val("text-indent"))) return true;

  // Clipped to nothing: the modern equivalent of the legacy `clip: rect(0…)`.
  // `inset(50%)`…`inset(100%)` (including fractional `inset(99.9%)`) collapse
  // the box, as does `circle(0)`. Decorative clips (`circle(50%)`, small
  // `inset`s, polygons) render visible content and are left alone.
  const clipPath = val("clip-path");
  if (
    clipPath &&
    /\b(?:inset\(\s{0,8}(?:[5-9]\d(?:\.\d+)?|100)%|circle\(\s{0,8}0(?![.\d]))/.test(
      clipPath,
    )
  )
    return true;
  if (isHidingTransform(val("transform"))) return true;
  if (isHidingFilter(val("filter"))) return true;

  // Same-color text on its background (white-on-white) and fully transparent
  // text are invisible to a human but plain text to the model. Colors are
  // canonicalized so `white`/`#fff`/`rgb(255,255,255)` mixes still compare.
  const color = canonicalizeColor(val("color"));
  if (color === "transparent") return true;
  const background =
    canonicalizeColor(val("background-color")) ||
    backgroundColor(val("background"));
  // Only flag same-color when BOTH sides resolve to a concrete color (`#rrggbb`
  // or `transparent`). `var(--x)`, `inherit`, and `currentColor` canonicalize to
  // their raw token, so two identical unresolved tokens (e.g. the ubiquitous
  // `color:var(--fg);background:var(--fg)` or `color:inherit;background:inherit`,
  // which resolve to DIFFERENT effective colors) would otherwise read as hidden
  // and splice out visible text. Fail open on anything we can't resolve.
  if (color && color === background && isConcreteColor(color)) return true;

  return isOverflowHidden(val);
}

// Scripting / resource-loading tags whose PRESENCE is reported to the model
// but whose content is preserved: their bodies are page source the model may
// legitimately need to inspect (how a page's scripts work, its styles, its
// SVGs), so unlike hidden elements they are never removed.
export const REPORTED_TAGS = new Set([
  "script",
  "style",
  "object",
  "embed",
  "iframe",
  "svg",
  "math",
]);

// HTML void elements: they never carry content and never emit a closing tag, so
// a hidden one (<img hidden>, <input hidden>, …) must be spliced as a single node
// — opening a balance region for it would run to the container's end (no close
// ever arrives) and delete the visible text that follows.
const VOID_ELEMENTS = new Set([
  "area",
  "base",
  "br",
  "col",
  "embed",
  "hr",
  "img",
  "input",
  "link",
  "meta",
  "param",
  "source",
  "track",
  "wbr",
]);

/**
 * True for an element a rendered page would not show: `hidden` attribute or a
 * hiding inline style. Works on both hast nodes and parseHtmlTag results.
 * @param {any} node
 * @returns {boolean}
 */
export function isHiddenElement(node) {
  if (node.type !== "element") return false;
  const { properties = {} } = node;
  if (properties.hidden !== undefined && properties.hidden !== null)
    return true;
  // `aria-hidden="true"` removes the element from the accessibility tree, so a
  // human using the rendered page never perceives it; a model reading raw
  // source still does. (rehype maps the attribute to the `ariaHidden` prop.)
  if (String(properties.ariaHidden).toLowerCase() === "true") return true;
  if (properties.style && isHiddenStyle(properties.style)) return true;
  return false;
}

/** @param {any} el */
function hasDataSrc(el) {
  return (
    typeof el.properties?.src === "string" &&
    el.properties.src.startsWith("data:")
  );
}

/**
 * @param {string} htmlValue
 * @returns {any}
 */
function parseHtmlTag(htmlValue) {
  const tree = unified().use(rehypeParse, { fragment: true }).parse(htmlValue);
  /** @type {any} */
  let firstElement = null;
  visit(tree, "element", (node) => {
    firstElement = node;
    return EXIT;
  });
  return firstElement;
}

// Returns null on a closing tag: `</x>` alone can never be the *start* of a
// hidden element, so only opens drive the surrounding loop's removal mode.
/**
 * @param {string} htmlValue
 * @returns {string | null}
 */
export function isHiddenOpen(htmlValue) {
  if (htmlValue.startsWith("</")) return null;
  const el = parseHtmlTag(htmlValue);
  if (!el) return null;
  if (isHiddenElement(el)) return el.tagName;
  return null;
}

// The lowercased name of an HTML closing tag (`</div>` -> "div"), or null when
// the value isn't a well-formed closing tag. The charset spans HTML custom-
// element and namespaced names (hyphens, dots, colons) so a close like
// `</foo-bar>` balances its matching open instead of throwing on a null match;
// callers treat null as "not the tag we're closing" and strip it as part of the
// surrounding removal region.
/**
 * @param {string} htmlValue
 * @returns {string | null}
 */
export function closingTagName(htmlValue) {
  // The charset is a superset of CommonMark's closing-tag grammar, so remark
  // never emits a `</…>` html node this fails to match; the null guard below is
  // defense-in-depth against a future parser/grammar change (hence unreachable).
  const match = htmlValue.match(/^<\/(?<tagName>[a-zA-Z][a-zA-Z0-9:._-]*)\s*>/);
  /* c8 ignore next */
  if (!match?.groups) return null;
  return match.groups.tagName.toLowerCase();
}

// ─── Layer 2: splice engine ──────────────────────────────────────────────────

export const COMMENT_PLACEHOLDER = "[HTML comment removed]";
export const HIDDEN_PLACEHOLDER = "[hidden HTML removed]";
// Shown when the remark/rehype parse itself fails (e.g. pathologically nested
// markup overflows the recursive tree walk with a RangeError). The top-level
// `sanitize`/`sanitizeText` contract is "never throws, `cleaned` is always a
// string", and this module is the only seam those callers own — so the HTML
// layer must fail CLOSED here: withhold the whole unparseable input behind one
// placeholder rather than let the exception escape and suppress all tool
// output. Withholding (not passing through) is the safe choice — content we
// could not inspect for hidden payloads is treated as if it were hidden.
export const UNPARSEABLE_PLACEHOLDER = "[HTML unparseable — withheld]";

/**
 * Replace each range of `text` with its kind's placeholder, preserving every
 * byte outside the ranges verbatim. Overlapping/nested ranges are merged
 * (defense-in-depth — the scanners emit disjoint ranges).
 * @param {string} text
 * @param {Array<{start: number, end: number, kind: "comment" | "hidden"}>} ranges
 * @returns {string}
 */
export function spliceRanges(text, ranges) {
  const sorted = [...ranges].sort(
    (left, right) => left.start - right.start || left.end - right.end,
  );
  /** @type {typeof ranges} */
  const merged = [];
  for (const range of sorted) {
    const last = merged[merged.length - 1];
    if (last && range.start < last.end) {
      if (range.end > last.end) last.end = range.end;
      // A hidden range absorbed into a comment range (the comment sorts first
      // on a tie) must keep the hidden label — hidden content placeholdered as
      // "[HTML comment removed]" would understate what was stripped. Hidden
      // dominates: if either side is hidden, the union is hidden.
      if (range.kind === "hidden") last.kind = "hidden";
    } else {
      merged.push({ ...range });
    }
  }
  let out = "";
  let cursor = 0;
  for (const range of merged) {
    out +=
      text.slice(cursor, range.start) +
      (range.kind === "comment" ? COMMENT_PLACEHOLDER : HIDDEN_PLACEHOLDER);
    cursor = range.end;
  }
  return out + text.slice(cursor);
}

/** @returns {{ tags: Record<string, number>, dataSrc: number }} */
function newWarned() {
  return { tags: {}, dataSrc: 0 };
}

/**
 * @param {ReturnType<typeof newWarned>} warned
 * @param {string} tagName
 */
function countTag(warned, tagName) {
  warned.tags[tagName] = (warned.tags[tagName] || 0) + 1;
}

/**
 * @param {ReturnType<typeof newWarned>} into
 * @param {ReturnType<typeof newWarned>} from
 */
function mergeWarned(into, from) {
  for (const [tag, count] of Object.entries(from.tags))
    into.tags[tag] = (into.tags[tag] || 0) + count;
  into.dataSrc += from.dataSrc;
}

/** @param {ReturnType<typeof newWarned>} warned */
function hasWarned(warned) {
  return warned.dataSrc > 0 || Object.keys(warned.tags).length > 0;
}

/**
 * Scan raw HTML for hidden content to strip and preserved tags to report.
 * Returned ranges are offsets into `html`; comments and hidden elements span
 * the whole element including its content (rehype positions cover open tag
 * through matching close, and parse5 extends an unclosed element to the end
 * of the fragment — fail-closed for truncated markup).
 * @param {string} html
 * @returns {{ ranges: Array<{start: number, end: number, kind: "comment" | "hidden"}>, warned: ReturnType<typeof newWarned> }}
 */
export function scanHtmlFragment(html) {
  const tree = unified().use(rehypeParse, { fragment: true }).parse(html);
  /** @type {Array<{start: number, end: number, kind: "comment" | "hidden"}>} */
  const ranges = [];
  const warned = newWarned();
  // @ts-ignore -- visit callback returns EXIT/SKIP only on matches; implicit undefined return is intentional
  // eslint-disable-next-line consistent-return
  visit(tree, (/** @type {any} */ node) => {
    const isComment = node.type === "comment";
    if (isComment || isHiddenElement(node)) {
      /* c8 ignore start -- parse5 omits positions only on recovery-synthesized
         elements (tbody and friends), which carry no attributes and so can
         never be hidden; fail closed on the whole fragment if that assumption
         ever breaks. */
      if (!node.position) {
        ranges.length = 0;
        ranges.push({ start: 0, end: html.length, kind: "hidden" });
        return EXIT;
      }
      /* c8 ignore stop */
      ranges.push({
        start: node.position.start.offset,
        end: node.position.end.offset,
        kind: isComment ? "comment" : "hidden",
      });
      return SKIP; // children are inside the spliced range
    }
    if (node.type !== "element") return; // eslint-disable-line consistent-return -- unist visit: undefined return means "continue", same as falling off the end
    if (REPORTED_TAGS.has(node.tagName)) countTag(warned, node.tagName);
    if (hasDataSrc(node)) warned.dataSrc += 1;
  });
  return { ranges, warned };
}

const mdParser = unified().use(remarkParse).use(remarkGfm);

// A markup-declaration-open (`<!`) or processing-instruction-ish (`<?`) start.
// Inside an inline html node these begin a *bogus comment* unless they open a
// proper `<!--…-->` comment (handled on the fast path) — `<!bogus>`, `<?php?>`,
// `<![CDATA[…]]>` all tokenize to comments the HTML-source branch already
// strips. The prose branch matched only literal `<!--`, so the bogus forms
// leaked through; this finds the candidates to validate.
const BOGUS_COMMENT_OPEN_RE = /<[!?]/g;

/**
 * If `value.slice(at)` begins with an HTML comment (proper or bogus), return
 * the comment's end offset *within `value`* (exclusive); else null. Validated
 * against the real HTML tokenizer rather than a hand-rolled bogus-comment state
 * machine, so we splice exactly what a browser would hide and never a `<Foo>`
 * element, a `<!doctype>`, or visible prose.
 * @param {string} value
 * @param {number} at offset of a candidate `<!`/`<?` within `value`
 * @returns {number | null}
 */
function bogusCommentEnd(value, at) {
  const tree = /** @type {any} */ (
    unified().use(rehypeParse, { fragment: true }).parse(value.slice(at))
  );
  // The slice starts at the candidate `<!`/`<?`, and an inline html node value
  // is a single construct, so the first parsed child IS that construct: a
  // `comment` node iff it tokenized to a (bogus) comment. A `<Foo>` element, a
  // `<!doctype>` (dropped, leaving following text), or nothing else qualifies.
  const first = tree.children[0];
  if (!first || first.type !== "comment") return null;
  return at + first.position.end.offset;
}

/**
 * Append comment ranges found in `value` to `ranges`.
 *
 * Proper `<!--…-->` comments are located with linear indexOf scanning (a lazy
 * `<!--[\s\S]*?-->` regex backtracks polynomially on crafted input); the close
 * search starts 2 chars in so spec-abrupt closes (`<!-->`, `<!--->`) terminate
 * their own comment. Other `<!`/`<?` starts are bogus comments, spliced to the
 * exact span the HTML tokenizer assigns them so the prose branch reaches parity
 * with the HTML-source branch (which strips them via parse5).
 * @param {string} value
 * @param {number} base absolute offset of the start of `value`
 * @param {number} nodeEnd absolute offset of the end of the containing node
 * @param {Array<{start: number, end: number, kind: "comment" | "hidden"}>} ranges
 */
function collectCommentRanges(value, base, nodeEnd, ranges) {
  BOGUS_COMMENT_OPEN_RE.lastIndex = 0;
  for (let match; (match = BOGUS_COMMENT_OPEN_RE.exec(value));) {
    const open = match.index;
    if (value.startsWith("<!--", open)) {
      const close = value.indexOf("-->", open + 2);
      /* c8 ignore start -- micromark only tokenizes inline comments WITH a
         terminator (an unterminated `<!--` in phrasing context stays literal
         text, visible to a human reader), so this is fail-closed
         defense-in-depth against a future tokenizer change. Unterminated
         comments in flow blocks are covered — parse5 handles them in
         scanHtmlFragment. */
      if (close === -1) {
        ranges.push({ start: base + open, end: nodeEnd, kind: "comment" });
        break;
      }
      /* c8 ignore stop */
      ranges.push({
        start: base + open,
        end: base + close + 3,
        kind: "comment",
      });
      BOGUS_COMMENT_OPEN_RE.lastIndex = close + 3;
      continue;
    }
    const end = bogusCommentEnd(value, open);
    // Not a comment (a `<Foo>` element, a `<!doctype>`, visible prose): leave
    // it untouched and resume scanning just past this `<`.
    if (end === null) continue;
    ranges.push({ start: base + open, end: base + end, kind: "comment" });
    BOGUS_COMMENT_OPEN_RE.lastIndex = end;
  }
}

/**
 * Update hidden-region state for one html node while inside a tracked region.
 *
 * Mutates `state` in place. A closing tag for the tracked element decrements
 * depth; reaching zero closes the range. A nested open of the same tag
 * increments depth. Any other close is swallowed inside the region.
 * @param {{ tag: string | null, depth: number, regionStart: number }} state
 * @param {string} value
 * @param {number} nodeEnd absolute end offset of this node
 * @param {Array<{start: number, end: number, kind: "comment" | "hidden"}>} ranges
 */
function updateHiddenState(state, value, nodeEnd, ranges) {
  if (value.startsWith("</")) {
    if (closingTagName(value) !== state.tag) return;
    state.depth--;
    if (state.depth === 0) {
      ranges.push({ start: state.regionStart, end: nodeEnd, kind: "hidden" });
      state.tag = null;
    }
    return;
  }
  const el = parseHtmlTag(value);
  if (el && el.tagName === state.tag) state.depth++;
}

/**
 * Balance-walk the direct children of a markdown container node: a hidden
 * open tag starts a removal region that runs to its matching close (or the
 * container's end when unbalanced — fail-closed), comments become single-node
 * ranges, and preserved tags are counted. Inline html is tokenized per TAG
 * (an element's content sits in sibling text nodes), which is why this walk
 * exists instead of handing the value to rehype.
 * @param {any} node
 * @param {Array<{start: number, end: number, kind: "comment" | "hidden"}>} ranges
 * @param {ReturnType<typeof newWarned>} warned
 */
function scanInlineChildren(node, ranges, warned) {
  const state =
    /** @type {{ tag: string | null, depth: number, regionStart: number }} */ ({
      tag: null,
      depth: 0,
      regionStart: 0,
    });
  for (const child of node.children) {
    if (child.type !== "html") continue;
    const value = child.value;
    const base = child.position.start.offset;
    if (state.depth > 0) {
      updateHiddenState(state, value, child.position.end.offset, ranges);
      continue;
    }
    // Comments can share an inline html node with neighboring constructs
    // (e.g. in a list item, `<!-- c -->!` is ONE node), so comment spans are
    // located within the value and spliced individually rather than assuming
    // the node IS the comment.
    collectCommentRanges(value, base, child.position.end.offset, ranges);
    const tagName = isHiddenOpen(value);
    if (tagName) {
      // A void element never emits a matching close, so a balance region would
      // extend to the container end and splice out following visible text. Emit
      // a single-node range instead (the flow/source branch already does this).
      if (VOID_ELEMENTS.has(tagName)) {
        ranges.push({
          start: base,
          end: child.position.end.offset,
          kind: "hidden",
        });
        continue;
      }
      state.tag = tagName;
      state.depth = 1;
      state.regionStart = base;
      continue;
    }
    if (value.startsWith("</")) continue;
    const el = parseHtmlTag(value);
    if (!el) continue;
    if (REPORTED_TAGS.has(el.tagName)) countTag(warned, el.tagName);
    if (hasDataSrc(el)) warned.dataSrc += 1;
  }
  if (state.depth > 0) {
    ranges.push({
      start: state.regionStart,
      end: node.position.end.offset,
      kind: "hidden",
    });
  }
}

// Containers whose direct html children are flow BLOCKS (complete markup —
// tags and content in one node value), as opposed to the phrasing containers
// (paragraph, heading, tableCell, emphasis, …) whose html children are
// per-tag fragments needing the balance walk.
const FLOW_HTML_PARENTS = new Set([
  "root",
  "blockquote",
  "listItem",
  "footnoteDefinition",
]);

/**
 * @param {string} text
 * @returns {{ ranges: Array<{start: number, end: number, kind: "comment" | "hidden"}>, warned: ReturnType<typeof newWarned> }}
 */
function scanMarkdown(text) {
  const tree = mdParser.parse(text);
  /** @type {Array<{start: number, end: number, kind: "comment" | "hidden"}>} */
  const ranges = [];
  const warned = newWarned();

  // Flow html blocks carry complete markup, so rehype locates comments/hidden
  // elements precisely within them; block-local offsets are shifted to
  // document coordinates.
  visit(tree, "html", (/** @type {any} */ node, _index, parent) => {
    if (!FLOW_HTML_PARENTS.has(parent?.type)) return;
    const base = node.position.start.offset;
    const sub = scanHtmlFragment(text.slice(base, node.position.end.offset));
    for (const range of sub.ranges) {
      ranges.push({
        start: base + range.start,
        end: base + range.end,
        kind: range.kind,
      });
    }
    mergeWarned(warned, sub.warned);
  });

  // Every phrasing container that holds inline html (paragraph, heading,
  // tableCell, emphasis, …) gets the balance walk — not just paragraphs, so a
  // hidden span inside a heading cannot slip through.
  visit(tree, (/** @type {any} */ node) => {
    if (FLOW_HTML_PARENTS.has(node.type) || !Array.isArray(node.children))
      return;
    if (
      !node.children.some((/** @type {any} */ child) => child.type === "html")
    )
      return;
    scanInlineChildren(node, ranges, warned);
  });

  return { ranges, warned };
}

// 30%-of-lines heuristic: HTML *source* gets scanned as one rehype fragment;
// inline tags scattered in prose go through the markdown branch instead.
/**
 * @param {string} text
 * @returns {boolean}
 */
export function looksLikeHtmlSource(text) {
  const lines = text.split("\n");
  if (lines.length < 5) return false;
  let htmlLines = 0;
  for (const line of lines) {
    if (/<\/?[a-zA-Z][^<>]*>/.test(line)) htmlLines++;
  }
  return htmlLines / lines.length > 0.3;
}

/**
 * Layer 2 over web-ingress text: splice out HTML comments and hidden elements
 * (placeholders mark the cuts; all other bytes are preserved verbatim) and
 * count preserved scripting/resource tags for the caller's warning. Returns
 * null when there is nothing to strip and nothing to report.
 * @param {string} text
 * @returns {{ text: string, removed: { comments: number, hidden: number }, warned: { tags: Record<string, number>, dataSrc: number } } | null}
 */
export function sanitizeHtml(text) {
  if (!HTML_TAG_PRESENT.test(text)) return null;
  /** @type {{ ranges: Array<{start: number, end: number, kind: "comment" | "hidden"}>, warned: ReturnType<typeof newWarned> }} */
  let scan;
  try {
    scan = looksLikeHtmlSource(text)
      ? scanHtmlFragment(text)
      : scanMarkdown(text);
  } catch {
    // The parse/visit blew up (stack overflow on pathological nesting, or any
    // other parser error). Fail CLOSED at this boundary so `sanitize`/
    // `sanitizeText` keep their never-throw contract: withhold the whole input
    // behind a placeholder and report it as hidden content removed.
    return {
      text: UNPARSEABLE_PLACEHOLDER,
      removed: { comments: 0, hidden: 1 },
      warned: newWarned(),
    };
  }
  const { ranges, warned } = scan;
  if (ranges.length === 0 && !hasWarned(warned)) return null;
  const removed = { comments: 0, hidden: 0 };
  for (const range of ranges)
    removed[range.kind === "comment" ? "comments" : "hidden"]++;
  return {
    text: ranges.length > 0 ? spliceRanges(text, ranges) : text,
    removed,
    warned,
  };
}

// ─── Layer 3: markdown/URL exfiltration detection ────────────────────────────

// Template-injection indicators, applied to the whole URL so they fire even
// when it is too malformed for `new URL()` to parse (e.g. a non-ASCII host).
// These are name-independent shapes — server-/client-side template syntax that
// only appears in a URL when something is interpolating untrusted data — so
// they carry signal on their own and need no value-shape gate.
//
// Keyword-PARAM detection (`?token=…`, `…#secret=…`) was REMOVED from this list
// (finding #20): firing on the parameter NAME alone flagged every `?session=ok`
// / `?key=pk_public_mapkey` / `?d=3`, drowning the real signal. A keyword
// param is now flagged only when its VALUE is payload-shaped, via the
// value-gated raw scan below (rawUrlKeywordExfil) which reuses the same
// blob/credential shape test as the post-parse param walk — see
// paramExfilReason. The raw scan keeps the pre-parse / fragment coverage the
// old name arm had (an unparseable host means `new URL()` throws and the
// post-parse walk never runs).
const EXFIL_INDICATORS = [/\$\{[^{}]+\}/, /\{\{[^{}]+\}\}/];

// Parameter NAMES whose presence used to flag on sight; now they only gate
// WHICH raw params the value-shape test is applied to before the URL is parsed.
// Kept narrow (the historically over-eager set) so the raw pre-parse pass stays
// cheap; any non-keyword param is still value-gated post-parse by the walk.
const KEYWORD_PARAM_NAME_RE =
  /^(?:data|d|payload|exfil|leak|steal|secret|token|key|env|password|pwd|cookie|session|auth)$/i;

const LONG_QUERY_THRESHOLD = 200;

// A `data:` URI carries its payload inline instead of pointing at a host, so
// the query/credential/fragment checks below never fire on it. Active-content
// types (HTML, SVG, JS) are a script-injection vector; an oversized blob of any
// type is an inline exfil/injection payload. A small inline image (icon) is
// left alone so the common case isn't drowned in noise.
const DATA_URI_ACTIVE_RE =
  /^\s*data:(?:text\/html|image\/svg\+xml|application\/(?:javascript|ecmascript|xhtml\+xml))[;,]/i;
export const DATA_URI_LENGTH_THRESHOLD = 4096;

// javascript:/vbscript: URIs execute on navigation/load, never a legitimate
// link target in fetched content — flagged regardless of payload.
const SCRIPT_URI_RE = /^\s*(?:javascript|vbscript):/i;

const RELATIVE_URL_BASE = "http://relative.invalid";

// Parameter NAMES that legitimately carry a LONG opaque (base64/hex) value, so
// a blob in one of them is NOT exfil: CDN request-signing (AWS SigV4 /
// CloudFront `X-Amz-*`/`Signature`/`Policy`/`Key-Pair-Id`, GCS `X-Goog-*`,
// Azure SAS `sv/sr/sig/se/sp/st/spr/skoid/sktid`), pagination cursors /
// continuation tokens, and the long analytics click-IDs. Matched
// case-insensitively against the exact (lowercased) parameter name. Scope is
// deliberately limited to names whose benign value is genuinely a long token —
// generic short params (`page`, `limit`, `v`, `t`, `cb`, …) are NOT listed,
// since their values never reach the blob threshold anyway and listing them
// would only widen the rename-dodge surface. A blob or credential-shaped value
// in any OTHER parameter still fires — this allowlist trades a narrow dodge
// (`?sig=<stolen>`) for not drowning the model in false positives on ordinary
// fetched pages.
const BENIGN_BLOB_PARAM_RE =
  /^(?:x-(?:amz|goog|ms|oss|obs)-[a-z0-9-]+|amz-[a-z0-9-]+|utm_[a-z]+|sig|signature|hmac|policy|credential|expires|key-pair-id|se|sp|sr|sv|st|spr|si|skoid|sktid|cursor|after|before|continuation|continuationtoken|continuation_token|pagetoken|page_token|nexttoken|next_token|gclid|fbclid|dclid|msclkid|gbraid|wbraid|_ga|_gl|mc_eid|mc_cid)$/i;

// matchesSecretHint is a deliberately broad PRE-gate whose bare-keyword arms
// (`token`, `secret`, `authorization`, …) also match ordinary hyphen/word
// delimited prose, and with no secret-redaction engine to refine the verdict
// here a weak digit proxy isn't enough: `login-authenticate-2024` and
// `the-secret-recipe-2024` clear "has a digit." A leaked credential is an
// OPAQUE, separator-free token, so the value must additionally contain a
// contiguous 20+ char `[A-Za-z0-9_]` run (no hyphen/space — that's what splits
// the prose runs below the bar) AND a digit before it counts as one.
const OPAQUE_TOKEN_RE = /[A-Za-z0-9_]{20,}/;
const VALUE_HAS_DIGIT_RE = /\d/;

// A value that is ENTIRELY a long base64 (40+ chars, optional `=` padding) or
// hex (32+ chars) run. Anchored to the whole value (operating on the RAW,
// un-decoded query so a `+` in base64 is not turned into a space), so a benign
// short value with an incidental hex word never trips it. Both arms are linear.
const BLOB_VALUE_B64_RE = /^[A-Za-z0-9+/]{40,}={0,2}$/;
const BLOB_VALUE_HEX_RE = /^[A-Fa-f0-9]{32,}$/;

// RFC 4648 §5 url-safe base64 substitutes `-`/`_` for `+`/`/`, so a payload
// encoded url-safe escapes the `[A-Za-z0-9+/]` arms above. Adding `-`/`_` to the
// charset would re-admit a long hyphenated word-slug (`the-secret-history-of-…`)
// as a "blob", so this arm additionally REQUIRES a contiguous 40+ char
// alphanumeric run: bulk-encoded bytes carry one (the separators `-`/`_` are
// rare in random base64url output), a human slug never does (every word breaks
// the run at a hyphen well under 40). The contiguous-run length matches the
// standard-base64 blob threshold, so the two arms agree on what counts as a
// blob. Anchored to the whole value for the same RAW-query reason as above.
const BLOB_VALUE_B64URL_RE = /^[A-Za-z0-9_-]{40,}={0,2}$/;
const B64URL_RUN_RE = /[A-Za-z0-9]{40,}/;

// A path segment whose whole value is a base64/hex run longer than any standard
// content hash (SHA-512 hex is 128, base64 88; SHA-256 hex 64) is bulk encoded
// data — a beacon URL that smuggles its payload in the path to dodge the query
// walk — rather than an asset fingerprint. The threshold sits just above the
// SHA-512-hex ceiling so every real fingerprint clears it while a ~150-char
// base64 of stolen cookies does not. Hyphens/underscores are excluded from the
// standard arm so a long word-slug (`the-secret-history-of-…`) is not mistaken
// for a payload; the url-safe arm re-admits `-`/`_` but, like the query arm
// above, gates on a contiguous 40+ alphanumeric run to keep the slug benign.
const PATH_BLOB_RE = /^(?:[A-Za-z0-9+/]+={0,2}|[A-Fa-f0-9]+)$/;
const PATH_BLOB_MIN_LEN = 128;

/**
 * True for an entirely-url-safe-base64 value carrying a contiguous 40+
 * alphanumeric run — a url-safe-encoded blob, distinguished from a hyphenated
 * slug (which never sustains a 40-char unbroken run). Shared by the query and
 * path blob detectors.
 * @param {string} value
 * @returns {boolean}
 */
function isBase64UrlBlob(value) {
  return BLOB_VALUE_B64URL_RE.test(value) && B64URL_RUN_RE.test(value);
}

/**
 * RAW (un-decoded) `name=value` pairs of a query/fragment string, split on `&`
 * and `;`. URLSearchParams is avoided on purpose: it percent-/`+`-decodes
 * values, turning a `+`-bearing base64 blob into a space-broken string that the
 * anchored blob regexes would miss.
 * @param {string} qs
 * @returns {Array<[string, string]>}
 */
function rawParams(qs) {
  /** @type {Array<[string, string]>} */
  const pairs = [];
  for (const pair of qs.split(/[&;]/)) {
    if (!pair) continue;
    const eq = pair.indexOf("=");
    const name = eq === -1 ? pair : pair.slice(0, eq);
    const value = eq === -1 ? "" : pair.slice(eq + 1);
    pairs.push([name.toLowerCase(), value]);
  }
  return pairs;
}

/**
 * Exfil reason for one URL parameter, or null. A credential-shaped value in any
 * non-allowlisted parameter (reusing the secret-shape gate), or a long
 * base64/hex blob in one. Allowlisted signing/pagination/analytics parameters
 * are skipped entirely (see BENIGN_BLOB_PARAM_RE).
 * @param {string} name  lowercased parameter name
 * @param {string} value RAW (un-decoded) value
 * @returns {string | null}
 */
function paramExfilReason(name, value) {
  if (BENIGN_BLOB_PARAM_RE.test(name)) return null;
  if (
    OPAQUE_TOKEN_RE.test(value) &&
    VALUE_HAS_DIGIT_RE.test(value) &&
    matchesSecretHint(value)
  )
    return "credential-shaped token in URL parameter";
  if (
    BLOB_VALUE_B64_RE.test(value) ||
    BLOB_VALUE_HEX_RE.test(value) ||
    isBase64UrlBlob(value)
  )
    return "suspicious query parameter";
  return null;
}

/**
 * Pre-parse, value-GATED keyword-parameter scan over the RAW URL string. Splits
 * off the query (`?…`) and fragment (`#…`) and applies the same blob/credential
 * value-shape test as the post-parse walk, but only to keyword-named params
 * (KEYWORD_PARAM_NAME_RE). This is the precision fix for finding #20: a keyword
 * param flags only when its value is actually payload-shaped, so `?session=ok`
 * and `?key=pk_public_mapkey` no longer fire. It runs BEFORE `new URL()` so a
 * blob in an unparseable-host URL (which the post-parse walk never reaches) is
 * still caught, preserving the coverage the old name-only arm had.
 * @param {string} url
 * @returns {string | null}
 */
function rawUrlKeywordExfil(url) {
  // Strip the scheme+authority+path prefix: everything up to the first `?`/`#`.
  const qIdx = url.search(/[?#]/);
  if (qIdx === -1) return null;
  for (const segment of url.slice(qIdx + 1).split("#")) {
    for (const [name, value] of rawParams(segment)) {
      if (!KEYWORD_PARAM_NAME_RE.test(name)) continue;
      const reason = paramExfilReason(name, value);
      if (reason) return reason;
    }
  }
  return null;
}

/**
 * True when every parameter of the parsed URL's query is in the benign
 * allowlist. Used to suppress the coarse long-query-string heuristic for
 * signed-CDN links, which are long by design. Only ever called once the query
 * is known to be long (and thus non-empty), so the vacuous-true empty case
 * cannot arise here.
 * @param {URL} parsed
 * @returns {boolean}
 */
function allParamsBenign(parsed) {
  return rawParams(parsed.search.slice(1)).every(([name]) =>
    BENIGN_BLOB_PARAM_RE.test(name),
  );
}

/**
 * Walk the query and fragment parameters of a parsed URL for an exfil reason.
 * @param {URL} parsed
 * @returns {string | null}
 */
function checkUrlParams(parsed) {
  for (const [name, value] of rawParams(parsed.search.slice(1))) {
    const reason = paramExfilReason(name, value);
    if (reason) return reason;
  }
  // The fragment carries the same `key=value` channel (`#token=…`); a bare
  // anchor (`#section-2`) yields one empty-value param that trips nothing.
  for (const [name, value] of rawParams(parsed.hash.slice(1))) {
    const reason = paramExfilReason(name, value);
    if (reason) return reason;
  }
  return null;
}

/**
 * A bulk encoded-data blob smuggled in a path segment (a beacon URL that avoids
 * query strings entirely), or null.
 * @param {URL} parsed
 * @returns {string | null}
 */
function checkUrlPath(parsed) {
  for (const segment of parsed.pathname.split("/")) {
    if (
      segment.length > PATH_BLOB_MIN_LEN &&
      (PATH_BLOB_RE.test(segment) || isBase64UrlBlob(segment))
    )
      return "encoded data blob in path segment";
  }
  return null;
}

/**
 * @param {string} url
 * @returns {string | null}
 */
export function checkExfilUrl(url) {
  if (/^\s*data:/i.test(url)) {
    if (DATA_URI_ACTIVE_RE.test(url)) return "active-content data: URI";
    if (url.length > DATA_URI_LENGTH_THRESHOLD)
      return "oversized inline data: payload";
    return null;
  }
  if (SCRIPT_URI_RE.test(url)) return "script-executing URI";
  if (EXFIL_INDICATORS.some((pattern) => pattern.test(url)))
    return "suspicious query parameter";
  // Value-gated keyword params, scanned on the RAW string so a blob in an
  // unparseable-host URL is caught before `new URL()` would throw.
  const keywordReason = rawUrlKeywordExfil(url);
  if (keywordReason) return keywordReason;
  // Userinfo and an oversized fragment are exfil channels the param walk misses:
  // credentials smuggled as `user:secret@host`, or a payload tucked in `#<blob>`.
  // Parse against a sentinel base so relative URLs don't throw.
  let parsed;
  try {
    parsed = new URL(url, RELATIVE_URL_BASE);
  } catch {
    return null;
  }
  if (parsed.username || parsed.password) return "embedded credentials";
  // A long query string is only suspicious when it carries a non-allowlisted
  // parameter — a signed-CDN URL is long by design (all `X-Amz-*`/SAS params).
  const qIdx = url.indexOf("?");
  if (
    qIdx !== -1 &&
    url.length - qIdx > LONG_QUERY_THRESHOLD &&
    !allParamsBenign(parsed)
  )
    return "unusually long query string";
  if (parsed.hash.length > LONG_QUERY_THRESHOLD)
    return "unusually long fragment";
  return checkUrlParams(parsed) || checkUrlPath(parsed);
}

/**
 * Host of a flagged URL — enough for the warning to name the destination
 * without echoing the payload-bearing query/fragment.
 * @param {string} url
 * @returns {string}
 */
export function urlHost(url) {
  // A `data:` URI has no host; name the channel rather than echoing the payload.
  if (/^\s*data:/i.test(url)) return "(inline data: URI)";
  let parsed;
  try {
    parsed = new URL(url, RELATIVE_URL_BASE);
  } catch {
    // checkExfilUrl flags via regex before parsing, so it can hand us a URL
    // WHATWG rejects (e.g. a non-ASCII host).
    return "(unparsable URL)";
  }
  if (
    parsed.origin === RELATIVE_URL_BASE &&
    !url.startsWith(RELATIVE_URL_BASE)
  ) {
    return "(relative URL)";
  }
  return parsed.host;
}

/**
 * True when `url` is an absolute, off-origin target (an authority that is not
 * the relative-resolution sentinel). Used for form `action`/`formaction` and
 * `meta refresh` URLs, where pointing off the page's own origin is the
 * exfil/redirect signal regardless of the query shape.
 * @param {string} url
 * @returns {boolean}
 */
function isOffOrigin(url) {
  let parsed;
  try {
    parsed = new URL(url, RELATIVE_URL_BASE);
  } catch {
    return false;
  }
  return (
    parsed.origin !== RELATIVE_URL_BASE || url.startsWith(RELATIVE_URL_BASE)
  );
}

/**
 * The redirect URL of a `<meta http-equiv="refresh">` content value
 * (`"5; url=https://…"`), or null when it carries no `url=` target.
 * @param {string} content
 * @returns {string | null}
 */
function metaRefreshUrl(content) {
  const match = /** @type {{ groups: { url: string } } | null} */ (
    content.match(/url\s*=\s*['"]?(?<url>[^'"\s;]+)/i)
  );
  return match ? match.groups.url : null;
}

/**
 * Candidate URLs of a `srcset` (a comma-separated "url descriptor" string) or
 * `ping` (a space-separated url list rehype delivers as an array) attribute.
 * Each candidate's leading whitespace-delimited token is its url (the trailing
 * `2x`/`100w` descriptor, or extra ping urls, are dropped to the next
 * candidate). An absent attribute (neither string nor array) yields none.
 * @param {unknown} value
 * @returns {string[]}
 */
function multiUrlAttr(value) {
  /** @type {string[]} */ let candidates = [];
  if (Array.isArray(value)) candidates = value.map(String);
  else if (typeof value === "string") candidates = value.split(",");
  return candidates
    .map((candidate) => candidate.trim().split(/\s+/)[0])
    .filter(Boolean);
}

/**
 * URL-bearing attributes of every HTML element in `text`, parsed with rehype so
 * quoting/casing/entities are handled correctly (no hand-rolled tag regex).
 * `context` selects the per-URL check the caller applies: resource URLs get the
 * exfil-shape test; form-submission and meta-refresh targets additionally flag
 * any absolute off-origin destination.
 * @param {string} text
 * @returns {Array<{ url: string, isImage: boolean, context: "resource" | "form" | "refresh" }>}
 */
function extractHtmlUrls(text) {
  const tree = unified().use(rehypeParse, { fragment: true }).parse(text);
  /** @type {Array<{ url: string, isImage: boolean, context: "resource" | "form" | "refresh" }>} */
  const urls = [];
  visit(tree, "element", (/** @type {any} */ node) => {
    // hast element nodes always carry a `properties` object (parse5 sets it).
    const props = node.properties;
    const isImage = node.tagName === "img";
    for (const key of ["src", "href", "background"])
      if (typeof props[key] === "string")
        urls.push({ url: props[key], isImage, context: "resource" });
    for (const key of ["srcSet", "ping"])
      for (const url of multiUrlAttr(props[key]))
        urls.push({ url, isImage, context: "resource" });
    for (const key of ["action", "formAction"])
      if (typeof props[key] === "string")
        urls.push({ url: props[key], isImage: false, context: "form" });
    // rehype delivers `http-equiv` as an array (comma-separated); join it back
    // so a `refresh` directive is matched regardless of how it was tokenized.
    const httpEquiv = Array.isArray(props.httpEquiv)
      ? props.httpEquiv.join(",").toLowerCase()
      : "";
    if (
      node.tagName === "meta" &&
      httpEquiv.includes("refresh") &&
      typeof props.content === "string"
    ) {
      const url = metaRefreshUrl(props.content);
      if (url) urls.push({ url, isImage: false, context: "refresh" });
    }
  });
  return urls;
}

// Reason for an off-origin submission/redirect target by context; null leaves
// the URL to the exfil-shape check alone.
const OFF_ORIGIN_REASON = {
  form: "off-origin form action",
  refresh: "off-origin meta-refresh redirect",
};

/**
 * Layer 3: report data-exfil-shaped URLs in markdown links/images/definitions
 * and HTML attributes (src/href/background/srcset/ping, form action/formaction,
 * meta-refresh). Detection only — the text is never modified; the caller
 * surfaces the threats as a warning.
 * @param {string} text
 * @returns {Array<{ isImage: boolean, reason: string, target: string }> | null}
 */
export function detectExfil(text) {
  if (!MD_LINK_HINT.test(text) && !HTML_TAG_PRESENT.test(text)) return null;

  /** @type {Array<{ isImage: boolean, reason: string, target: string }>} */
  const threats = [];

  try {
    // Remark AST handles markdown links/images/definitions (balanced parens,
    // reference links) correctly, unlike a hand-rolled regex.
    const tree = mdParser.parse(text);
    visit(tree, (node) => {
      if (
        node.type !== "link" &&
        node.type !== "image" &&
        node.type !== "definition"
      )
        return;
      const reason = checkExfilUrl(node.url);
      if (!reason) return;
      threats.push({
        isImage: node.type === "image",
        reason,
        target: urlHost(node.url),
      });
    });

    // HTML attributes (not AST nodes in remark).
    for (const { url, isImage, context } of extractHtmlUrls(text)) {
      const reason =
        checkExfilUrl(url) ||
        (context !== "resource" && isOffOrigin(url)
          ? OFF_ORIGIN_REASON[context]
          : null);
      if (!reason) continue;
      threats.push({ isImage, reason, target: urlHost(url) });
    }
  } catch {
    // The parse/visit blew up (stack overflow on pathological nesting). Fail
    // CLOSED so the never-throw contract holds: report one sentinel threat so
    // the caller still warns rather than crashing, since an input too nested to
    // scan could itself be hiding an exfil URL.
    return [
      {
        isImage: false,
        reason: "input too deeply nested to scan for exfil URLs",
        target: "(unparseable HTML)",
      },
    ];
  }

  return threats.length > 0 ? threats : null;
}
