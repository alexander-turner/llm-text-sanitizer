# llm-text-sanitizer

Strip common prompt injection surfaces.

A small utility for cleaning untrusted text before it reaches an LLM —
removing the patterns most often abused to smuggle instructions into a
model (hidden Unicode, control characters, fake system/tool delimiters,
and similar).

## Status

Early scaffolding. The repo is wired up with the
[claude-automation-template](https://github.com/alexander-turner/claude-automation-template)
for CI, git hooks, and Claude Code automation.

## Setup

```bash
./setup.sh
```

This configures git hooks and installs dependencies. Verify the output
ends with `✓ Setup complete!`.

## Automation

This repository uses the Claude automation template. See `CLAUDE.md` for
the conventions Claude Code sessions follow here, and `.github/workflows/`
for the CI and `@claude` integration. Template improvements sync in daily
via `template-sync.yaml` (requires a `TEMPLATE_SYNC_TOKEN` repo secret).
