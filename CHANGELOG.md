# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to
adhere to [Semantic Versioning](https://semver.org/).

<!-- Record user-facing changes under the "## Unreleased" heading below, using Keep a Changelog headings (### Added, ### Changed, ### Deprecated, ### Removed, ### Fixed, ### Security). On push to main the auto-version workflow promotes the Unreleased block to a dated version section; leave it empty when there is nothing user-facing. -->

## Unreleased

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
