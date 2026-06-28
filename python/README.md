# agent-input-sanitizer (Python client)

A thin Python bridge to the [`agent-input-sanitizer`](https://github.com/alexander-turner/agent-input-sanitizer)
Node.js CLI. The sanitization logic has a single source of truth — the
JavaScript in `src/` — so this package shells out to the CLI rather than
re-implementing it, giving a Python pipeline byte-identical verdicts with no
second implementation to keep in sync.

## Requirements

- Node.js (>= 20) on `PATH`. There is deliberately no pure-Python fallback.
- The path to a JavaScript checkout's CLI. The wheel does **not** bundle the JS
  (a vendored copy would drift), so set `AGENT_SANITIZER_CLI` to the
  `bin/sanitize-cli.mjs` of a cloned/`npm install`-ed checkout. When imported
  directly from a repo checkout, the CLI is found automatically.

## Usage

```python
from agent_input_sanitizer import sanitize

result = sanitize("untrusted text", html=True)
print(result.cleaned, result.found, result.warnings)
```

See the package docstring for the full set of entry points (`sanitize_text`,
`classify_prompt`, `scan_instruction_files`, `clean_file`, and the long-lived
`Sanitizer` worker).
