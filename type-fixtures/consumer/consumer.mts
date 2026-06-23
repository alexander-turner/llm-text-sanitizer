// Consumer-perspective type fixture. This file is NOT part of the library; it
// imports the package by name (resolving through the published `exports` map to
// the GENERATED `.d.mts` declarations, exactly as a downstream project does)
// and asserts the public types are what we promise. The accompanying
// types-consumer.test.mjs builds the declarations and type-checks this file.
//
// Crucially this catches declaration-EMIT regressions our own `pnpm check`
// cannot: `pnpm check` type-checks the `.mjs` source (where a regex literal is
// obviously `RegExp`), but the bug class here is a `.d.mts` that emits `any` at
// the package boundary — invisible until something resolves the package by name.

import {
  sanitize,
  CATEGORY,
  SECRET_HINT,
  SECRET_HINT_EXT,
  matchesSecretHint,
} from "agent-input-sanitizer";
import { STRIP, SGR_RE, stripInvisible } from "agent-input-sanitizer/invisible";
import { HTML_TAG_PRESENT, MD_LINK_HINT } from "agent-input-sanitizer/html";

// `0 extends 1 & T` is only true when T is `any`, so this flags the exact
// regression that shipped in 1.0.1: a declaration that widened to `any`. A bare
// `const r: RegExp = X` would NOT catch it, because `any` is assignable to
// anything — the whole point is to fail when the type has collapsed to `any`.
type IsAny<T> = 0 extends 1 & T ? true : false;

// Regex exports must stay `RegExp`, never `any`.
const _secretNotAny: IsAny<typeof SECRET_HINT> = false;
const _secretExtNotAny: IsAny<typeof SECRET_HINT_EXT> = false;
const _stripNotAny: IsAny<typeof STRIP> = false;
const _sgrNotAny: IsAny<typeof SGR_RE> = false;
const _tagNotAny: IsAny<typeof HTML_TAG_PRESENT> = false;
const _mdNotAny: IsAny<typeof MD_LINK_HINT> = false;
const _secret: RegExp = SECRET_HINT;
const _secretExt: RegExp = SECRET_HINT_EXT;

// CATEGORY keeps its literal-keyed type, so a code typo is a compile error.
const _cf: "cf-format" = CATEGORY.CF;
// @ts-expect-error — an unknown category key must not type-check.
CATEGORY.NOT_A_REAL_CATEGORY;

const _hint: boolean = matchesSecretHint("token=abc");
const _stripped: string = stripInvisible("x");

// sanitize resolves to the documented result shape.
const result = await sanitize("x", { html: true });
const _cleaned: string = result.cleaned;
const _found: string[] = result.found;
const _warnings: string[] = result.warnings;

// Reference the bindings so noUnusedLocals (if ever enabled) and readers both
// see them as load-bearing assertions, not dead code.
export const _assertions = [
  _secretNotAny,
  _secretExtNotAny,
  _stripNotAny,
  _sgrNotAny,
  _tagNotAny,
  _mdNotAny,
  _secret,
  _secretExt,
  _cf,
  _hint,
  _stripped,
  _cleaned,
  _found,
  _warnings,
] as const;
