---
name: Bug report
about: Report incorrect sanitizer behavior (a missed or over-eager transform)
title: ""
labels: bug
assignees: ""
---

> **Security vulnerability?** Do **not** file it here—report it privately per
> [SECURITY.md](../../SECURITY.md).

## What happened

A clear description of the bug.

## Entry point

Which import/op is involved (e.g. `/invisible`, `/html`, `/confusables`,
`/instructions`, `/prompt`, `/output`, `/rehydrate`, the CLI, or the Python
client).

## Reproduction

The smallest input that triggers it. Use a credential-shaped **placeholder**
for any secret-like value—never a real credential.

```js
// input + the call you made
```

## Expected vs. actual

- **Expected:** what the sanitizer should have returned.
- **Actual:** what it returned (`cleaned` / `found` / `warnings`, the verdict,
  or the error).

## Environment

- Package version:
- Node version:
- OS:
