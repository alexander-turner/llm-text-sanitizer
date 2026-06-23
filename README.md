# `agent-input-sanitizer`

Sanitize untrusted text **before any model sees it**—in an agent, RAG, or
tool-use pipeline. Provider-agnostic: it cleans bytes, not prompts. Every entry
point is a pure transform or a function with an **injected** I/O/engine seam, so
nothing about a specific agent harness (Claude, or any other) is baked in.

The core cleaners, split across entry points so the heavy HTML dependency stays
opt-in:

1. **Invisible-char + ANSI stripping** (`./invisible`, zero runtime deps) —
   removes zero-width spaces, bidi controls, variation selectors, tag
   characters, ANSI/SGR escapes, and other hidden code points used to smuggle
   instructions. Preserves ZWNJ/ZWJ where scripts (Arabic, Indic, emoji)
   require them. The composite `applyLayer1` (ANSI + invisibles, lone-surrogate
   safe) is re-exported from the package root.
2. **Hidden-HTML splicing** (`./html`)—splices out instructions buried in
   comments, `display:none`, off-screen, white-on-white, `hidden`/`aria-hidden`,
   etc. Leaves a placeholder; preserves every other byte verbatim.
3. **Exfil-URL detection** (`./html`, detection only)—reports URLs shaped to
   leak data off-origin (payloads in query/path, embedded credentials,
   `data:`/`javascript:` targets, off-origin redirects). Reports, never edits.

Built on those, entry points covering each ingress an agent has:

4. **Confusable/homoglyph folding** (`./confusables`)—fold look-alike glyphs in
   tool-call **input** fields (paths, commands) to their ASCII canon, closing a
   cross-script deny-rule bypass. The homoglyph scanner is **injected**
   (`{ scan }`).
5. **Instruction-file scanning** (`./instructions`)—scan/auto-clean
   `CLAUDE.md` / `AGENTS.md` / `SKILL.md` / any markdown that loads as model
   context, decoding Unicode-tag and zero-width-binary payloads. The target file
   set is a **caller-supplied glob set**.
6. **User-prompt verdict** (`./prompt`)—classify a submitted prompt as
   pass / pass-with-SGR-note / block on payload-capable invisible/ANSI content.
7. **Tool-output pipeline** (`./output`)—run Layers 1–4 over structured tool
   output, preserving its shape. Layer 4 (secret redaction) is an **injected**
   redactor; an optional Layer-5 slot takes a filter that returns _verbatim
   spans to delete_, so even a compromised filter can only remove bytes.
8. **Edit-repair / rehydration** (`./rehydrate`, `./view-map`)—re-anchor an
   Edit/Write the model composed from the _sanitized_ view back onto the real
   on-disk bytes, substitute redaction placeholders with the real secrets, and
   **deny** any call that can’t be unambiguously anchored or that would expose a
   secret in the next view. Without this, sanitizing a file’s view silently
   breaks the agent’s ability to edit it. File access and the redactor are
   injected via `io`.

See [THREAT-MODEL.md](./THREAT-MODEL.md) for per-vector detail.

```sh
npm install agent-input-sanitizer
```

## Usage

### Convenience function

```js
import { sanitize } from "agent-input-sanitizer";

// Layer 1 only (invisible chars + ANSI), no heavy deps:
const { cleaned, found, warnings } = await sanitize(untrustedText);

// Opt into the HTML layers for web/HTML ingress:
const result = await sanitize(fetchedPageSource, { html: true });
//   result.cleaned   — hidden HTML spliced out, placeholders left in place
//   result.found     — stable category codes neutralized (e.g. ["cf-format", "hidden-html"])
//   result.warnings  — human-facing notices (long-run alerts, exfil reasons, …)
```

`sanitize` never throws and never silently drops content: any change to the
text comes with at least one `warnings` entry. The `{ html: true }` path
lazy-loads the HTML deps, so a Layer-1-only caller never pays for them.

### Zero-dependency invisible-char core

```js
import {
  stripInvisible,
  stripInvisibleWithReport,
} from "agent-input-sanitizer/invisible";

stripInvisible(text); // -> cleaned string
const { cleaned, found } = stripInvisibleWithReport(text);
//   found names exactly the category codes removed, e.g. ["variation-selectors"]
```

### HTML layer

Heavier—it pulls in the unified/remark/rehype graph (~200 ms of module-load
time). Import it directly only when you need it.

```js
import {
  sanitizeHtml,
  detectExfil,
  checkExfilUrl,
} from "agent-input-sanitizer/html";

const cleaned = sanitizeHtml(pageSource); // null when nothing to strip/report
const threats = detectExfil(pageSource); // null or [{ isImage, reason, target }]
const reason = checkExfilUrl(oneUrl); // null or a string reason
```

### Agent-pipeline entry points

Each takes plain arguments and returns plain results; agent-specific concerns
(homoglyph engine, secret redactor, file access, hook envelope) are injected, so
none of them know about any particular agent harness.

```js
// Confusable folding — inject your homoglyph scanner.
import { normalizeConfusables } from "agent-input-sanitizer/confusables";
const folded = normalizeConfusables(
  "Bash",
  { command: "/аpt update" },
  {
    scan: (text) => myHomoglyphEngine.scan(text), // -> { findings:[{ index, char, latinEquivalent }] }
  },
);
//   null when nothing changed, else { updatedInput, normalized }

// Instruction files — pass YOUR glob set.
import {
  scanInstructionFiles,
  cleanFile,
} from "agent-input-sanitizer/instructions";
const findings = scanInstructionFiles(
  ["CLAUDE.md", "AGENTS.md", "**/SKILL.md", ".claude/**/*.md"],
  { cwd: projectDir },
);
for (const { file } of findings) cleanFile(`${projectDir}/${file}`);

// User prompt — pass/note/block verdict.
import { classifyPrompt } from "agent-input-sanitizer/prompt";
const verdict = classifyPrompt(submittedPrompt); // { action: "pass" | "note" | "block", reason? }

// Tool output — Layers 1–4, redactor injected, optional Layer-5 spans slot.
import { sanitizeText } from "agent-input-sanitizer/output";
const out = await sanitizeText(toolText, {
  html: isWebPage,
  exfilScan: isUntrustedIngress,
  redact: async (t) => myRedactor.redact(t), // -> { text, found, note? } | null
  filterInjection: (t) => mySemanticFilter(t), // -> { removeSpans, warning } | null
});

// Edit-repair — re-anchor a model-authored Edit onto real on-disk bytes.
import { rehydrateRedacted } from "agent-input-sanitizer/rehydrate";
const repaired = await rehydrateRedacted("Edit", toolInput, {
  readFile: (p) => fs.readFileSync(p, "utf8"),
  redactMap: (t) => myRedactor.map(t), // -> { text, pairs } | { unmappable }
  redact: (t) => myRedactor.redact(t), // -> string | null
});
//   { updatedInput, context } | { deny } | null  — a deny never exposes a secret
```
