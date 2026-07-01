# agent-input-sanitizer (Python client)

A thin Python bridge to the [`agent-input-sanitizer`](https://github.com/alexander-turner/agent-input-sanitizer)
Node.js CLI. The sanitization logic has a single source of truth — the
JavaScript in `src/` — so this package shells out to the CLI rather than
re-implementing it, giving a Python pipeline byte-identical verdicts with no
second implementation to keep in sync.

## Requirements

- **Node.js (>= 22) on `PATH`.** The sanitizer is JavaScript; something has to
  run it. There is deliberately no pure-Python fallback.

That's it — `pip install agent-input-sanitizer` and, with Node available, you're
ready to go. The wheel ships a self-contained, single-file build of the CLI
(the `src/` logic and its npm dependencies bundled into one `.mjs` at release
time), so there is no separate JavaScript checkout to clone and no environment
variable to set. The bundle is a versioned build artifact from `src/`, not a
hand-maintained port, so it can't drift from the JS.

### Optional: point at your own JS checkout

Set `AGENT_SANITIZER_CLI` to a checkout's `bin/sanitize-cli.mjs` to override the
bundled CLI (e.g. to run against unreleased `src/` changes). When the module is
imported directly from a repo checkout, the source CLI is found automatically.

## Usage

```python
from agent_input_sanitizer import sanitize

result = sanitize("untrusted text", html=True)
print(result.cleaned, result.found, result.warnings)
```

See the package docstring for the full set of entry points (`sanitize_text`,
`classify_prompt`, `scan_instruction_files`, `clean_file`, and the long-lived
`Sanitizer` worker).

## Versioning

This package is versioned in lockstep with the npm
[`agent-input-sanitizer`](https://www.npmjs.com/package/agent-input-sanitizer):
each release publishes both at the same version from the same commit, and the
wheel bundles `src/` at exactly that version. So `pip install
agent-input-sanitizer==X.Y.Z` and `npm i agent-input-sanitizer@X.Y.Z` are the
same underlying logic.
