/**
 * Fast-check property tests for Layer 3 (exfil-URL detection).
 *
 * The headline invariant is the THREAT-MODEL promise: a reported threat names
 * the destination `host` and *never* echoes the payload-bearing query, path,
 * fragment, or userinfo. A leak there is the same shape of bug as a passthrough
 * — the output looks fine until you assert the thing it must not contain — so
 * it gets an explicit positive postcondition rather than trusting the inputs to
 * wander onto it. Plus crash-resistance: the detectors run a markdown parser
 * and the WHATWG URL parser on fully untrusted input and must never throw.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { detectExfil, checkExfilUrl, urlHost } from "../src/html.mjs";
import { fcRunOptions } from "./test-helpers.mjs";

const runOptions = fcRunOptions({ numRuns: 500 });

// A long opaque blob standing in for exfiltrated data. ≥210 chars clears every
// length threshold (path segment > 128, fragment > 200), so all four placement
// positions below reliably produce a flagged threat — keeping the host-no-leak
// property non-vacuous across the whole position space, not just the query case.
const secretBlob = fc
  .array(
    fc.constantFrom(
      ..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".split(
        "",
      ),
    ),
    { minLength: 210, maxLength: 280 },
  )
  .map((chars) => chars.join(""));

const exfilHost = fc.constantFrom(
  "evil.example",
  "beacon.test",
  "a.b.attacker.invalid",
);

// One case carries a single secret through both the doc and the assertion, so
// the host-no-leak check is meaningful: the secret sits in the query/fragment/
// path/userinfo — never the authority — so a correct urlHost returns the bare
// host and a buggy one that echoed any payload-bearing component would fail
// `target === host`. (The earlier independent-secret form was vacuous: a 210+
// char blob can never be a substring of a sub-20-char host regardless of bugs.)
const exfilCase = fc
  .tuple(
    exfilHost,
    secretBlob,
    fc.constantFrom("query", "fragment", "path", "userinfo"),
    fc.constantFrom("md-link", "md-image", "html-a", "html-img"),
  )
  .map(([host, secret, where, kind]) => {
    const url = {
      query: `https://${host}/p?data=${secret}`,
      fragment: `https://${host}/p#${secret}`,
      path: `https://${host}/${secret}`,
      userinfo: `https://user:${secret}@${host}/p`,
    }[where];
    const doc = {
      "md-link": `see [here](${url}) now`,
      "md-image": `look ![alt](${url}) here`,
      "html-a": `<a href="${url}">x</a>`,
      "html-img": `<img src="${url}">`,
    }[kind];
    return { host, secret, doc };
  });

describe("property: detectExfil host never echoes the payload", () => {
  it("a flagged threat's target is the bare host, never the payload", () => {
    let sawFlagged = 0;
    fc.assert(
      fc.property(exfilCase, ({ host, doc }) => {
        const threats = detectExfil(doc) ?? [];
        for (const threat of threats)
          assert.equal(
            threat.target,
            host,
            `target should be the bare host, got ${JSON.stringify(threat.target)}`,
          );
        if (threats.length > 0) sawFlagged += 1;
      }),
      runOptions,
    );
    assert.ok(sawFlagged > 0, "no doc was ever flagged — property vacuous");
  });
});

// ─── Crash resistance over arbitrary input ───────────────────────────────────

const urlishToken = fc.constantFrom(
  "https://",
  "http://",
  "data:",
  "javascript:",
  "vbscript:",
  "//",
  "?data=",
  "#",
  "@",
  ":",
  "/",
  "user:pw@",
  "${x}",
  "{{y}}",
  ".com",
  "evil.example",
  "AAAA",
  "%ff",
  "\\",
);
const arbitraryUrlish = fc
  .array(fc.oneof(fc.string({ maxLength: 20 }), urlishToken), { maxLength: 12 })
  .map((parts) => parts.join(""));

const docToken = fc.constantFrom(
  "](",
  "![",
  "[ref]: ",
  "<a href=",
  '<img src="',
  "<meta http-equiv=refresh content=",
  '">',
  ")",
  " ",
);
const arbitraryDoc = fc
  .array(fc.oneof(arbitraryUrlish, docToken, fc.string({ maxLength: 20 })), {
    maxLength: 16,
  })
  .map((parts) => parts.join(""));

describe("property: Layer 3 never throws on arbitrary input", () => {
  it("detectExfil returns null or an array of well-formed threats", () => {
    fc.assert(
      fc.property(arbitraryDoc, (doc) => {
        const result = detectExfil(doc);
        assert.ok(result === null || Array.isArray(result));
        for (const threat of result ?? []) {
          assert.equal(typeof threat.isImage, "boolean");
          assert.equal(typeof threat.reason, "string");
          assert.ok(threat.reason.length > 0);
          assert.equal(typeof threat.target, "string");
        }
      }),
      runOptions,
    );
  });

  it("checkExfilUrl returns null or a non-empty reason string", () => {
    fc.assert(
      fc.property(arbitraryUrlish, (url) => {
        const reason = checkExfilUrl(url);
        assert.ok(reason === null || typeof reason === "string");
        if (typeof reason === "string") assert.ok(reason.length > 0);
      }),
      runOptions,
    );
  });

  it("urlHost always returns a string", () => {
    fc.assert(
      fc.property(arbitraryUrlish, (url) => {
        assert.equal(typeof urlHost(url), "string");
      }),
      runOptions,
    );
  });
});
