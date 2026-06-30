/**
 * Edit-repair: re-anchor an Edit/Write composed from a sanitized file view back
 * onto the real on-disk bytes.
 *
 * Sanitizing the model's view of a file makes that view diverge from disk in
 * two ways: Layer 1 strips ANSI escapes and payload-capable invisible
 * characters, and secret redaction replaces secrets with [REDACTED…]
 * placeholders. An Edit whose old_string was copied from that view then fails
 * exact-match against the real file, and a whole-file Write would persist
 * placeholder text over the real secret. This module closes the loop without
 * ever showing the model a secret: it re-derives the sanitized view of the
 * target file (the shared {@link applyLayer1}, then the injected redactor's
 * map mode), locates the model's old_string in that view, and maps it
 * span-exact back to the on-disk bytes — across both placeholder expansion and
 * stripped invisible runs (the offset machinery lives in `./view-map.mjs`).
 * Placeholders in new_string are substituted with the secrets they stand for;
 * invisible characters inside the replaced region go with it, while runs
 * outside the span are preserved untouched. The secret flows disk → tool input
 * only; the model's next view is sanitized again.
 *
 * Security invariant: rehydration must never *expose* a secret. Before
 * rewriting, the would-be post-edit content is re-sanitized and the call is
 * denied if any rehydrated secret would survive in the model's next view of
 * the file (e.g. an edit that relabels `password=` to a field the redactor
 * skips). Every unresolvable case fails closed as a deny whose reason tells the
 * model how to restructure the call; nothing is ever silently written with
 * placeholder text standing in for a secret.
 *
 * I/O is INJECTED through `io`: the caller supplies file reads and the secret
 * redactor (its map/plain contract). The package never bundles a redactor —
 * detect-secrets, a daemon, or any other engine is the caller's to wire.
 */
import { applyLayer1 } from "./layer1.mjs";
import {
  occurrences,
  alignDeletions,
  resolveSpan,
  rehydrateNewString,
} from "./view-map.mjs";

// Cheap gate: every redaction placeholder the canonical redactor emits starts
// with this. A caller whose placeholders differ overrides it via the `hint`
// option below.
export const DEFAULT_HINT = "[REDACTED";

/**
 * Map-mode response from the redactor: either the mappable view (text + ordered
 * (placeholder, original, start) pairs) or an unmappable verdict carrying its
 * reason — a discriminated pair.
 * @typedef {{text: string, pairs: {placeholder: string, original: string, start: number}[]}
 *   | {unmappable: string}} RedactMapView
 */

/**
 * Injected I/O. `readFile` returns the file's bytes (throwing on a missing or
 * unreadable path). `redactMap` returns the redacted view of (Layer-1-cleaned)
 * file text plus the ordered (placeholder, original, start) pairs, or an
 * `{unmappable}` verdict. `redact` returns the plain redacted text, or null
 * when nothing was redacted. `redactMap`/`redact` are the only secret-engine
 * seam; they may be async and are awaited.
 * @typedef {{ readFile: (path: string) => string,
 *   redactMap: (text: string) => Promise<RedactMapView> | RedactMapView,
 *   redact: (text: string) => Promise<string|null> | (string|null) }} RehydrateIo
 */

/**
 * Count of secrets the model's *next* sanitized view of `newContent` would
 * reveal, excluding any already visible in the prior view (no regression
 * there). The next view is Layer 1 then redaction, exactly as a PostToolUse
 * sanitizer derives it.
 * @param {string[]} secrets rehydrated values written into newContent
 * @param {string} priorView sanitized view of the file before the change
 * @param {string} newContent would-be post-change file content
 * @param {RehydrateIo} io
 * @returns {Promise<number>}
 */
async function exposedSecrets(secrets, priorView, newContent, io) {
  const candidates = [...new Set(secrets)].filter(
    (value) => !priorView.includes(value),
  );
  if (candidates.length === 0) return 0;
  const { cleaned } = applyLayer1(newContent);
  const redacted = (await io.redact(cleaned)) ?? cleaned;
  return candidates.filter((value) => redacted.includes(value)).length;
}

/** @param {number} count */
function exposureDeny(count) {
  return (
    `this change would move ${count} secret value(s) into a context the redactor no ` +
    `longer recognizes, so the next read of the file would reveal them; keep each ` +
    `secret under its recognizable field name, or ask the user to make this change`
  );
}

/**
 * @param {{file_path: string, old_string: string, new_string: string, replace_all?: boolean}} ti
 * @param {string} content disk bytes
 * @param {string} cleaned Layer-1 view of `content`
 * @param {{text: string, pairs: {placeholder: string, original: string, start: number}[]}} view
 * @param {{start: number, deleted: string}[]} deletions
 * @param {RehydrateIo} io
 * @param {boolean} hinted the input itself carries placeholders
 * @param {string} hint placeholder prefix
 */
async function rehydrateEdit(
  ti,
  content,
  cleaned,
  view,
  deletions,
  io,
  hinted,
  hint,
) {
  const oldS = ti.old_string;
  // An empty old_string is not a view span the model copied — in real Edit it
  // is the create/insert-at-anchor case, which Edit handles itself. There is
  // nothing to re-anchor; pass through (null) so Edit surfaces its own
  // behavior and the empty needle never reaches occurrences.
  if (oldS === "") return null;
  // Resolve against the VIEW first — it is the only thing the model can have
  // copied from. A verbatim disk match is only trusted when the view has no
  // match: on a divergent file, raw bytes can contain an accidental match
  // spanning a stripped sequence's tail, which would mis-anchor the edit.
  const viewOcc = occurrences(view.text, oldS);
  if (viewOcc.length === 0) {
    // Not in the model's view. A verbatim disk match means the input targets
    // literal bytes (e.g. literal "[REDACTED]" prose); new_string still goes
    // through the resolver (with an empty span) so a placeholder referencing a
    // secret elsewhere in the file is denied with guidance instead of being
    // written out literally.
    if (content.includes(oldS)) {
      const literalRes = rehydrateNewString(
        oldS,
        ti.new_string,
        [],
        view.pairs,
      );
      return "deny" in literalRes ? literalRes : null;
    }
    // Without placeholders this is an ordinary stale/typo'd old_string; pass
    // through so the model gets Edit's familiar not-found error.
    if (!hinted) return null;
    return {
      deny:
        `old_string contains ${hint}…] placeholders but does not match the sanitized ` +
        `view of ${ti.file_path}; re-read the file and copy the placeholder text exactly`,
    };
  }
  if (viewOcc.length > 1 && !ti.replace_all)
    return {
      deny:
        `old_string matches ${viewOcc.length} locations in the sanitized view of ` +
        `${ti.file_path}, and the view can differ from disk at each (redacted ` +
        `secrets, stripped invisible characters); add surrounding context to make it unique`,
    };

  const spans = [];
  for (const start of viewOcc) {
    const resolved = resolveSpan(
      content,
      cleaned,
      view,
      deletions,
      start,
      start + oldS.length,
    );
    if (resolved === null)
      return {
        deny: `old_string starts or ends inside a ${hint}…] placeholder; include each placeholder whole`,
      };
    spans.push(resolved);
  }
  if (new Set(spans.map((span) => span.diskText)).size > 1)
    return {
      deny:
        `replace_all matched occurrences whose on-disk bytes differ (distinct secrets ` +
        `or invisible characters) in ${ti.file_path}; edit each occurrence separately ` +
        `with unique context`,
    };

  // Identical view spans hide identical disk text, so every span carries the
  // same placeholder/original sequence — resolve new_string against the first.
  const span = spans[0];
  // Soundness gate (see resolveSpan): greedy deletion alignment can anchor a
  // view span to the wrong disk bytes when a stripped run abuts kept text it
  // resembles. Refuse on either symptom:
  //   (a) the resolved bytes do not re-clean to the span's view — the run stole
  //       a visible character (an ANSI sequence ending in "m" before a kept "m");
  //   (b) the bytes carry an interior stripped run yet the plain old_string also
  //       exists verbatim on disk — a purely-invisible collision (e.g. a
  //       zero-width char inside an otherwise-identical run) re-cleans cleanly,
  //       so (a) misses it, but a verbatim clean occurrence means the model's
  //       text could equally well anchor there. Either way the anchor is
  //       ambiguous; fail closed rather than edit the wrong region.
  const anchorAmbiguous =
    applyLayer1(span.diskText).cleaned !== span.cleanedText ||
    (span.diskText !== oldS && content.includes(oldS));
  if (anchorAmbiguous)
    return {
      deny:
        `the matched region sits next to stripped control sequences that cannot be ` +
        `re-anchored unambiguously in ${ti.file_path}; edit a smaller region away ` +
        `from them, or ask the user to make this change`,
    };
  const newRes = rehydrateNewString(
    oldS,
    ti.new_string,
    span.pairs,
    view.pairs,
  );
  if ("deny" in newRes) return newRes;

  // The span is byte-identical to disk (no pairs, no interior runs): nothing
  // to translate. The empty-span resolver above already vetted new_string.
  if (span.diskText === oldS && newRes.text === ti.new_string) return null;

  // Simulate the post-edit content for the exposure check. When the disk
  // old_string is not unique and replace_all is off, Edit itself will refuse
  // the call, so nothing is written and there is nothing to check.
  const diskOcc = occurrences(content, span.diskText);
  let updated = null;
  if (ti.replace_all) updated = content.split(span.diskText).join(newRes.text);
  else if (diskOcc.length === 1)
    updated =
      content.slice(0, diskOcc[0]) +
      newRes.text +
      content.slice(diskOcc[0] + span.diskText.length);
  if (updated !== null) {
    const exposed = await exposedSecrets(
      newRes.secrets,
      view.text,
      updated,
      io,
    );
    if (exposed > 0) return { deny: exposureDeny(exposed) };
  }

  const notes = [
    span.pairs.length > 0 &&
      `${hint}…] placeholders were resolved to the file's real secret values (still hidden from you)`,
    span.invisibleBytes > 0 &&
      `the matched region carries ${span.invisibleBytes} invisible/control character(s) stripped from your view; they are replaced along with it`,
  ].filter(Boolean);
  return {
    updatedInput: { ...ti, old_string: span.diskText, new_string: newRes.text },
    context: `Edit input was translated to the file's actual on-disk bytes: ${notes.join("; ")}.`,
  };
}

/**
 * @param {{file_path: string, content: string}} ti
 * @param {{text: string, pairs: {placeholder: string, original: string, start: number}[]}} view
 * @param {RehydrateIo} io
 * @param {string} hint placeholder prefix
 */
async function rehydrateWrite(ti, view, io, hint) {
  const texts = [...new Set(view.pairs.map((pair) => pair.placeholder))].filter(
    (phText) => ti.content.includes(phText),
  );
  // None of the file's redaction placeholders appear: content is literal.
  if (texts.length === 0) return null;

  let out = ti.content;
  const secrets = [];
  for (const phText of texts) {
    const produced = view.pairs.filter((pair) => pair.placeholder === phText);
    if (occurrences(view.text, phText).length > produced.length)
      return {
        deny:
          `${ti.file_path} mixes literal "${phText}" text with a redacted secret sharing ` +
          `that placeholder; cannot tell which occurrences in the new content are ` +
          `which — use Edit with unique surrounding context instead`,
      };
    const values = [...new Set(produced.map((pair) => pair.original))];
    if (values.length > 1)
      return {
        deny:
          `multiple distinct secrets in ${ti.file_path} share the placeholder "${phText}", ` +
          `so a whole-file Write cannot tell which is which; use Edit with unique ` +
          `surrounding context for each`,
      };
    out = out.split(phText).join(values[0]);
    secrets.push(values[0]);
  }

  const exposed = await exposedSecrets(secrets, view.text, out, io);
  if (exposed > 0) return { deny: exposureDeny(exposed) };

  return {
    updatedInput: { ...ti, content: out },
    context:
      `Write content contained ${hint}…] placeholders; they were resolved to the ` +
      `file's real secret values on disk (still hidden from you), so the secrets ` +
      `are preserved in the written file.`,
  };
}

/**
 * True when this tool call could need re-anchoring against the target file's
 * sanitized view: any well-formed Edit (the view may differ from disk even
 * without placeholders, via stripped invisible characters), or a Write whose
 * content carries a placeholder.
 * @param {string} tool
 * @param {any} ti
 * @param {string} hint
 */
function isCandidate(tool, ti, hint) {
  if (typeof ti?.file_path !== "string") return false;
  if (tool === "Edit")
    return (
      typeof ti.old_string === "string" && typeof ti.new_string === "string"
    );
  if (tool === "Write")
    return typeof ti.content === "string" && ti.content.includes(hint);
  return false;
}

/**
 * Re-anchor an Edit/Write input composed from a sanitized file view back onto
 * the on-disk bytes (secrets rehydrated, stripped invisible runs re-attached).
 * Returns the rewritten input plus a model-facing context line, a deny with an
 * instructive reason when the input is unresolvable or would expose a secret,
 * or null when there is nothing to do. Throws only on internal error (the
 * caller fails closed).
 *
 * `io` is the injected I/O (file read + redactor map/plain). `hint` is the
 * redaction-placeholder prefix (defaults to {@link DEFAULT_HINT}); override it
 * only if the injected redactor emits a different placeholder shape.
 * @param {string} tool
 * @param {any} toolInput
 * @param {RehydrateIo} io
 * @param {{ hint?: string }} [options]
 * @returns {Promise<{updatedInput: any, context: string} | {deny: string} | null>}
 */
export async function rehydrateRedacted(
  tool,
  toolInput,
  io,
  { hint = DEFAULT_HINT } = {},
) {
  // A notebook cell carrying a placeholder would persist it verbatim over the
  // secret; mapping .ipynb JSON is not supported, so refuse with guidance.
  if (
    tool === "NotebookEdit" &&
    typeof toolInput?.new_source === "string" &&
    toolInput.new_source.includes(hint)
  )
    return {
      deny:
        `new_source contains a ${hint}…] placeholder, which stands for a secret ` +
        `hidden from your view; rehydration is not supported for notebooks. Keep ` +
        `the secret-bearing cell unchanged, or ask the user to edit it.`,
    };
  if (!isCandidate(tool, toolInput, hint)) return null;
  const hinted =
    tool === "Write" ||
    toolInput.old_string.includes(hint) ||
    toolInput.new_string.includes(hint);

  let content;
  try {
    content = io.readFile(toolInput.file_path);
  } catch {
    // Missing/unreadable target: an Edit fails on its own; a Write creates a
    // new file whose placeholder text can only be literal content.
    return null;
  }
  const { cleaned } = applyLayer1(content);
  // A Layer-1-clean file's view differs from disk only at placeholders, which
  // a hint-free old_string cannot touch: a verbatim match needs no
  // translation, and a mismatch is an ordinary stale old_string Edit should
  // report itself. Either way the redactor is skipped.
  if (!hinted && cleaned === content) return null;

  const deletions = alignDeletions(content, cleaned);
  const view = await io.redactMap(cleaned);
  if ("unmappable" in view) {
    if (!hinted) return null;
    return {
      deny: `cannot resolve redaction placeholders in ${toolInput.file_path}: ${view.unmappable}`,
    };
  }
  // View identical to disk: any placeholders in the input are literal text.
  if (view.pairs.length === 0 && deletions.length === 0) return null;

  return tool === "Edit"
    ? rehydrateEdit(
        toolInput,
        content,
        cleaned,
        view,
        deletions,
        io,
        hinted,
        hint,
      )
    : rehydrateWrite(toolInput, view, io, hint);
}
