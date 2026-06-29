# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to
adhere to [Semantic Versioning](https://semver.org/).

<!-- Do NOT hand-edit this file. On push to main the auto-version workflow drafts the next release's notes from the Conventional Commit subjects since the last tag, then promotes "## Unreleased" to a dated version section. Your commit messages are the source of truth — keep the empty "## Unreleased" heading below in place. -->

## Unreleased

## [1.3.2] - 2026-06-29

### Fixed

- HTML parser now fails closed on overflow and detects exponent/negative CSS and base64url exfiltration attempts.

## [1.3.0] - 2026-06-29

### Added

- Python client is now installable via `pyproject.toml`, with a README for setup and usage.
- Cross-language golden tests for process lifecycle validation across Python and Node.js implementations.

### Fixed

- Named regex group for grandchild-pid matching in test utilities.

## [1.2.16] - 2026-06-29

### Fixed

- Prompt classification now blocks 8-bit C1 CSI/OSC ANSI introducers to maintain consistent security with the sanitizer's ANSI detection.

## [1.2.15] - 2026-06-29

### Added
- SECURITY.md file documenting security policies and responsible disclosure.
- CONTRIBUTING.md file with contribution guidelines.
- GitHub issue and pull request templates to standardize submissions.
- Documentation for the ./view-map utility.
- Fuzz coverage testing with property-suite input domain validation against threat codepoints.
- Smoke test for pack-and-install with OS and Node version matrix coverage.

### Changed
- Improved release publishing to match npm publish-conflict errors by error code instead of stderr text matching.

### Fixed
- Instructions: exclusive temp write without symlink following, and reporting of mixed-encoding runs.
- Rehydrate: fail gracefully on empty old_string instead of throwing RangeError.
- Invisible: capped and flagged carve-out-preserved joiners to close zero-width covert channel.
- Dependabot configuration with cooldown settings across all ecosystems.
- Python-client CI matrix pinned to Node 22 for pnpm compatibility.

### Removed
- Unused bin/lib/retry.bash script.

## [1.2.10] - 2026-06-29

### Fixed

- CLI now correctly executes when launched through a `node_modules/.bin` symlink.
- Output handling improved with recursion depth bounding, cycle detection, and flagging of hidden characters in object keys.

## [1.2.8] - 2026-06-28

### Fixed
- Fixed npm package to stop shipping build artifacts, resolving issues with consumer installations.
- Fixed worker-mode buffering to respect the input size cap on a per-line basis.

## [1.2.6] - 2026-06-28

### Fixed

- HTML documents containing only processing instructions are now routed through the sanitizer correctly.

### Changed

- Documentation updated to prefer precision over recall in the detection layers.

## [1.2.5] - 2026-06-28

### Fixed

- Strip bogus comments in prose and value-gate keyword exfiltration parameters in HTML processing.

## [1.2.3] - 2026-06-28

### Fixed
- HTML text-hiding detection now catches more CSS techniques to prevent leaking of invisible text
- Layer1 processor now handles OSC payloads, strips zero-width combining marks, recognizes C1 SGR sequences, and caps joiner runs
- Instructions scanner now safely skips dangling symlinks in the working directory instead of aborting
- CLI/Python bridge is now hardened against hangs, crashes, and oversized input
- Instructions scanning is now contained to the working directory with symlink refusal and atomic writes

## [1.2.1] - 2026-06-28

### Fixed
- Fold search/list tool fields in confusables and fail loudly on scanner offset mismatch

## [1.2.0] - 2026-06-23

### Changed

- docs: rework README into a scannable entry-point table
- feat(cli): bridge classifyPrompt, sanitizeText, and instruction-file ops
- docs: compact the Non-JS pipelines README section
- fix(python): fork-safety, clearer errors, and transport fuzzing
- style: format cli.test.mjs with prettier
- fix(python): harden the persistent worker against stderr deadlock and leaks
- test: isolate session-setup git from ambient insteadOf rewriting
- feat(python): amortize HTML module-load via an auto-spun shared worker
- feat: add stdin/stdout CLI and Python client for non-JS pipelines

## [1.1.1] - 2026-06-23

### Changed

- ci(mutation): drop redundant fetch fallback in change gate
- ci(mutation): run Stryker as a required PR check
- test(mutation): kill surviving mutants with exact-assertion guards
- test(mutation): add Stryker mutation testing for src/*.mjs

## [1.1.0] - 2026-06-23

### Changed

- fix: bound ANSI_RE private-intro class to kill polynomial backtracking (CodeQL js/polynomial-redos
- feat: add agent-pipeline entry points (input, output, prompt, instructions, edit-repair)

## [1.0.4] - 2026-06-23

### Changed

- ci(format-autofix): skip cleanly when AUTOFIX_TOKEN is absent
- docs: generate changelog from commits, stop hand-editing Unreleased
- ci: auto-apply prettier on pull requests
- style: apply prettier to README
- test(types): typecheck the emitted declarations as a consumer
- fix(types): annotate SECRET_HINT regexes as RegExp

## [1.0.3] - 2026-06-23

### Changed

- ci: drop security-vulnerability-scan workflow
- ci: run security scan monthly instead of weekly
- ci: run template-sync weekly instead of daily
- ci: drop @claude responder, pin security scan to Sonnet

## [1.0.2] - 2026-06-23

### Changed

- fix(release): base version on the reachable tag, not the global highest
- docs: recommend opening a PR when work is complete; dedupe changelog
- fix(release): bump from max of npm and highest tag
- docs: release 1.0.1 [skip ci]
- fix(release): declare repository metadata for npm provenance
- ci(release): adopt punctilio auto-version flow
- docs(changelog): add fragment for version-update release rework
- ci(release): publish release without an explicit tag push
- Update README to format project title as code
- Update README by removing install and license sections
- ci: guard that a package.json bump ships its CHANGELOG section
- docs(changelog): roll changelog.d fragments into 1.0.1 section

## [1.0.1] - 2026-06-22

### Added

- `CATEGORY` (the stable `found` codes) and `CATEGORY_LABELS` (code→human-label map) exports, available from both the root and `./invisible` entries.
- `LINGUISTIC_SCRIPTS` is now re-exported from the root entry, matching the documented public surface.
- `typecheck` and `coverage` npm scripts, so the commands documented in the README resolve.

### Changed

- **BREAKING:** `found` (from `sanitize` and `stripInvisibleWithReport`) now reports **stable machine-readable codes** (`cf-format`, `variation-selectors`, `blank-fillers`, `ansi`, `lone-surrogates`, `html-comments`, `hidden-html`, `exfil-urls`) instead of human prose. Branch on these; display strings now live exclusively in `warnings` and in the new `CATEGORY_LABELS` map.

### Fixed

- Packaging: guard that the published tarball ships a `.d.mts` declaration for every `exports` subpath, so `agent-input-sanitizer`, `/html`, and `/invisible` resolve to real types under strict `checkJs` instead of silently falling back to untyped `.mjs` (the `v1.0.0` regression).

## [1.0.0] - 2026-06-22

### Added

- Layer 1 (`./invisible`, zero runtime deps): strips payload-capable invisible Unicode—format `Cf` characters, variation selectors, blank-rendering fillers, soft hyphens, interior BOMs, and Unicode tag characters—plus ANSI/SGR escape sequences, while preserving ZWNJ/ZWJ where an orthography requires them.
- Layer 2 (`./html`): byte-preserving splicing of human-invisible HTML—comments, CSS-hidden and attribute-hidden elements—reporting scripting/resource tags without removing them.
- Layer 3 (`./html`): detection-only reporting of data-exfil URLs in markdown links/images and HTML attributes.
- `sanitize` convenience entry point plus the `./invisible` and `./html` subpath exports.
