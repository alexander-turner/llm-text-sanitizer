#!/usr/bin/env node
/**
 * Single-source-of-truth CLI over the sanitizer's data-in/data-out entry points,
 * for non-JS pipelines.
 *
 * The logic lives once, in `src/`. This CLI is the supported escape hatch for
 * callers that can't import the JavaScript directly (a Python pipeline, say): it
 * speaks JSON over stdin/stdout so any language drives the exact same verdicts
 * without a second implementation to keep in sync. Only the entry points with no
 * injected callback are exposed — the agent-pipeline seams that take a homoglyph
 * scanner, redactor, or file-access object have no language-agnostic wire form
 * and stay JS-only.
 *
 * Protocol — a request is a JSON object with an `op` (default `"sanitize"` so a
 * bare `{ text, html }` keeps working). Per op:
 *
 *   sanitize           { text, html? }            -> { cleaned, found, warnings }
 *   sanitizeText       { text, html?, exfilScan? } -> { cleaned, warnings, modified, sgrNote }
 *   classifyPrompt     { text }                    -> { action, reason? }
 *   scanInstructionFiles { globs, cwd? }           -> { findings: [{ file, findings }] }
 *   cleanFile          { path }                    -> { changed }
 *
 * A failure response is `{ "error": string }`. Two modes, same binary:
 *
 *   one-shot (default): read ONE JSON object from stdin (may span lines), write
 *     ONE response line. A malformed request propagates — non-zero exit, stack
 *     on stderr — so a scripted caller fails loudly.
 *
 *   worker (`--worker`): read newline-delimited JSON requests until EOF, write
 *     EXACTLY one response line per input line, in order — including for a blank
 *     line (a framing slip on the caller's side), which gets an `{ "error" }`
 *     line rather than being silently skipped. Skipping a line desyncs every
 *     later response against a client that reads one response per request. A
 *     malformed request likewise yields an `{ "error" }` line and the worker
 *     keeps serving — the specific, necessary recovery that makes a long-lived
 *     process usable across independent requests (one bad line must not drop the
 *     whole pipe). JSON string-encodes every newline, so one request and one
 *     response always occupy one line each.
 *
 * Input-size cap: both modes reject a single request larger than
 * `AGENT_SANITIZER_MAX_INPUT_BYTES` (UTF-8 bytes, default 10 MiB) with a
 * structured error rather than buffering an unbounded payload into memory —
 * one-shot exits non-zero, the worker emits an `{ "error" }` line and keeps
 * serving. Raise or lower the limit via that environment variable.
 */
import { Buffer } from "node:buffer";
import { realpathSync } from "node:fs";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { sanitize } from "../src/index.mjs";

/** Largest single request accepted, in UTF-8 bytes. Caps memory per request so
 * a hostile or runaway caller can't OOM the process; override via the env var. */
const DEFAULT_MAX_INPUT_BYTES = 10 * 1024 * 1024;

/** Resolve the configured input cap, falling back to the default for an unset,
 * empty, non-numeric, or non-positive value. */
function maxInputBytes() {
  const raw = process.env.AGENT_SANITIZER_MAX_INPUT_BYTES;
  const parsed = Number(raw);
  if (
    raw === undefined ||
    raw === "" ||
    !Number.isFinite(parsed) ||
    parsed <= 0
  )
    return DEFAULT_MAX_INPUT_BYTES;
  return Math.floor(parsed);
}

/** Throw if `text` exceeds the configured byte cap. The message names the limit
 * and the env var so a caller can act on it. */
function enforceSizeLimit(text) {
  const limit = maxInputBytes();
  const size = Buffer.byteLength(text, "utf8");
  if (size > limit)
    throw new Error(
      `request too large: ${size} bytes exceeds the ${limit}-byte limit ` +
        "(raise AGENT_SANITIZER_MAX_INPUT_BYTES to accept it)",
    );
}

/** @param {Record<string, unknown>} req @param {string} key */
function requireString(req, key) {
  if (typeof req[key] !== "string")
    throw new Error(`request.${key} must be a string`);
}

/** Operations the CLI exposes. Each takes the parsed request, returns the JSON
 * payload object. Non-`sanitize` modules are imported lazily so a caller that
 * only ever sanitizes never loads prompt/output/instructions code. */
const OPS = {
  async sanitize(req) {
    requireString(req, "text");
    const { cleaned, found, warnings } = await sanitize(req.text, {
      html: Boolean(req.html),
    });
    return { cleaned, found, warnings };
  },

  async sanitizeText(req) {
    requireString(req, "text");
    // Layers 1–3 only: redact (Layer 4) and filterInjection (Layer 5) are
    // injected JS callbacks with no wire form, so they're never set here.
    const { sanitizeText } = await import("../src/output.mjs");
    const { cleaned, warnings, modified, sgrNote } = await sanitizeText(
      req.text,
      {
        html: Boolean(req.html),
        exfilScan: Boolean(req.exfilScan),
      },
    );
    return { cleaned, warnings, modified, sgrNote };
  },

  async classifyPrompt(req) {
    requireString(req, "text");
    const { classifyPrompt } = await import("../src/prompt.mjs");
    return classifyPrompt(req.text);
  },

  async scanInstructionFiles(req) {
    if (
      !Array.isArray(req.globs) ||
      req.globs.some((g) => typeof g !== "string")
    )
      throw new Error("request.globs must be an array of strings");
    const { scanInstructionFiles } = await import("../src/instructions.mjs");
    const opts = typeof req.cwd === "string" ? { cwd: req.cwd } : {};
    return { findings: scanInstructionFiles(req.globs, opts) };
  },

  async cleanFile(req) {
    requireString(req, "path");
    const { cleanFile } = await import("../src/instructions.mjs");
    return { changed: cleanFile(req.path) };
  },
};

/**
 * Run one request through the named `op` and serialize the response.
 * Throws on a malformed request or unknown op; the caller decides whether that
 * propagates (one-shot) or becomes an `{ error }` line (worker).
 * @param {string} payload  a single JSON request object
 * @returns {Promise<string>} a single-line JSON response
 */
async function handle(payload) {
  enforceSizeLimit(payload);
  const request = JSON.parse(payload);
  const op = request.op ?? "sanitize";
  const run = Object.prototype.hasOwnProperty.call(OPS, op) ? OPS[op] : null;
  if (!run) throw new Error(`unknown op: ${op}`);
  return JSON.stringify(await run(request));
}

/** Read the whole stream as UTF-8, aborting as soon as the accumulated bytes
 * exceed the cap so a hostile one-shot caller can't force unbounded buffering.
 * @param {NodeJS.ReadableStream} stream */
async function readAll(stream) {
  stream.setEncoding("utf8");
  const limit = maxInputBytes();
  let text = "";
  let bytes = 0;
  for await (const chunk of stream) {
    bytes += Buffer.byteLength(chunk, "utf8");
    if (bytes > limit)
      throw new Error(
        `request too large: input exceeds the ${limit}-byte limit ` +
          "(raise AGENT_SANITIZER_MAX_INPUT_BYTES to accept it)",
      );
    text += chunk;
  }
  return text;
}

/**
 * Streaming newline-splitter that never buffers a line past the byte `limit`.
 *
 * Fed raw stdin chunks one at a time, it yields a sequence of events the worker
 * turns into exactly one response line each. The reason this exists instead of
 * `readline`: `readline` buffers an entire newline-less line into memory before
 * handing it over, so a hostile caller streaming a multi-gigabyte line with no
 * `\n` defeats the size cap (the cap only fires once the whole line is already
 * resident). Here the running byte length of the CURRENT unterminated line is
 * tracked as bytes arrive; the instant it exceeds `limit` the partial buffer is
 * dropped and the splitter enters a "resync" state that discards every byte up
 * to (and including) the next `\n`, so peak buffering for one line is bounded by
 * `limit` plus one chunk — never the whole line.
 *
 * Events: `{ kind: "line", text }` for a complete in-cap line (trailing `\r`
 * stripped, matching `readline`'s `crlfDelay: Infinity` CRLF handling), and
 * `{ kind: "oversize" }` for a line whose bytes crossed `limit` (emitted once,
 * at the newline that terminates the discarded line). The worker maps the
 * former through `handle` and the latter to a "request too large" error line, so
 * the one-response-per-input-line framing holds even for a dropped line.
 *
 * @param {number} limit  per-line byte cap (`maxInputBytes()`)
 */
function createLineSplitter(limit) {
  // The bytes of the current line are held as a LIST of chunk slices plus their
  // running total, joined into one Buffer only when the line completes. Pushing
  // a slice is O(1), so assembling an N-byte line costs O(N) overall. The old
  // single growing `Buffer.concat([buffer, segment])` per segment re-copied the
  // whole accumulated prefix each time — O(N^2) for a line streamed as many
  // small chunks (e.g. a multi-MiB line arriving in 1-byte reads). `discarding`
  // still caps peak buffering at `limit`: once a line would breach it, the
  // pending slices are dropped and we scan only for the terminating `\n`.
  /** @type {Buffer[]} */
  let pending = [];
  let pendingLen = 0;
  let discarding = false;

  /** Drop any pending slices (line abandoned or fully consumed). */
  const reset = () => {
    pending = [];
    pendingLen = 0;
  };

  /** Join the pending slices into one line buffer (single copy) and reset. */
  const take = () => {
    const buf =
      pending.length === 1 ? pending[0] : Buffer.concat(pending, pendingLen);
    reset();
    return buf;
  };

  /** Strip one trailing `\r` so CRLF input frames identically to LF. */
  const toLine = (buf) => {
    const stripCr = buf.length > 0 && buf[buf.length - 1] === 0x0d;
    return buf.toString("utf8", 0, stripCr ? buf.length - 1 : buf.length);
  };

  // Fold one segment (the bytes of the current line seen so far in this chunk)
  // into the pending list, flipping to `discarding` if it would breach the cap.
  // Applies identically to a newline-terminated segment and to the unterminated
  // tail, so an oversize line is caught WITHIN a chunk, not only at its edge.
  const accumulate = (segment) => {
    if (discarding) return;
    if (pendingLen + segment.length > limit) {
      reset();
      discarding = true;
      return;
    }
    if (segment.length > 0) {
      pending.push(segment);
      pendingLen += segment.length;
    }
  };

  /** Feed one chunk, returning the events it completes (newline-terminated). */
  const push = (chunk) => {
    const events = [];
    let start = 0;
    for (let i = 0; i < chunk.length; i++) {
      if (chunk[i] !== 0x0a) continue;
      accumulate(chunk.subarray(start, i));
      if (discarding) {
        events.push({ kind: "oversize" });
        discarding = false;
        reset();
      } else {
        events.push({ kind: "line", text: toLine(take()) });
      }
      start = i + 1;
    }
    accumulate(chunk.subarray(start));
    return events;
  };

  /**
   * Flush at EOF. A final line with no trailing `\n` is still a request, so it
   * gets a response — matching `readline`, which emits its last line on `close`.
   * An empty tail (stream ended on a `\n`, or was empty) yields nothing.
   */
  push.end = () => {
    if (discarding) {
      discarding = false;
      reset();
      return [{ kind: "oversize" }];
    }
    if (pendingLen === 0) return [];
    return [{ kind: "line", text: toLine(take()) }];
  };

  return push;
}

const OVERSIZE_ERROR = (limit) =>
  JSON.stringify({
    error:
      `request too large: input exceeds the ${limit}-byte limit ` +
      "(raise AGENT_SANITIZER_MAX_INPUT_BYTES to accept it)",
  });

async function runWorker() {
  // Stream raw bytes (no encoding) so the splitter tracks UTF-8 byte length, not
  // decoded characters, and a multi-gigabyte newline-less line is discarded as
  // it streams rather than buffered whole the way `readline` would.
  const limit = maxInputBytes();
  const split = createLineSplitter(limit);

  // EXACTLY one response line per input line. A complete in-cap line goes
  // through `handle`; its try/catch is the worker's reason to exist — a single
  // malformed request reports an error and serving continues rather than
  // tearing down a pipe other requests still use. An oversize line (its bytes
  // crossed the cap, so it was discarded unbuffered) gets the same structured
  // "request too large" error a one-shot caller sees. `response` never holds a
  // newline: `JSON.stringify` of the result or of a one-key error object is
  // single-line, so the one-line-per-request framing holds.
  const respond = async (event) => {
    if (event.kind === "oversize") {
      process.stdout.write(`${OVERSIZE_ERROR(limit)}\n`);
      return;
    }
    let response;
    try {
      response = await handle(event.text);
    } catch (err) {
      response = JSON.stringify({ error: err?.message ?? String(err) });
    }
    process.stdout.write(`${response}\n`);
  };

  for await (const chunk of process.stdin) {
    for (const event of split(Buffer.from(chunk))) await respond(event);
  }
  for (const event of split.end()) await respond(event);
}

async function runOneShot() {
  // Fail loudly but cleanly: a bad request (or a contract-impossible `sanitize`
  // throw) exits non-zero with a one-line reason on stderr — not a raw Node
  // stack, which leaks internals and is noise for a scripted caller. The
  // message carries the sanitizer-CLI prefix so a wrapping client can attribute
  // the failure to this bridge.
  let response;
  try {
    response = await handle(await readAll(process.stdin));
  } catch (err) {
    process.stderr.write(`sanitize CLI: ${err?.message ?? String(err)}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`${response}\n`);
}

// Run only when invoked as a script, not when imported (a unit test imports
// `createLineSplitter` directly and must not have the worker consume its stdin).
// Compare REAL paths: the published bin is launched through a
// `node_modules/.bin/sanitize-cli` symlink, so `process.argv[1]` is the symlink
// path while `import.meta.url` is this module's real file — a raw URL compare
// would be false and the CLI would silently produce no output. `realpathSync`
// resolves both to the same on-disk file. A non-existent `argv[1]` (e.g. an
// `--eval` entry) throws ENOENT and is treated as "not our script".
function invokedAsScript() {
  if (process.argv[1] === undefined) return false;
  try {
    return (
      realpathSync(process.argv[1]) ===
      realpathSync(fileURLToPath(import.meta.url))
    );
  } catch {
    return false;
  }
}
if (invokedAsScript())
  await (process.argv.includes("--worker") ? runWorker() : runOneShot());

export { createLineSplitter };
