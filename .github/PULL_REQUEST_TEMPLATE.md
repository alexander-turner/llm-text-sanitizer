## Summary

What problem does this solve, and why this approach?

## Changes

- ...

## Tests / verification

How did you verify this? (`pnpm test`, new property/negative tests, manual
repro, etc.)

## Checklist

- [ ] Commits follow [Conventional Commits](https://www.conventionalcommits.org/);
      each subject reads as a user-facing release note.
- [ ] `pnpm test`, `pnpm lint`, and `pnpm check` pass locally.
- [ ] New or changed detectors have negative tests (zero findings on legitimate
      input) and pin their invariants with property/fuzz tests.
- [ ] No real secrets/tokens in the diff, tests, or description.
- [ ] `CHANGELOG.md` and `package.json` version are left untouched (the release
      workflow owns them).
