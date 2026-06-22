#!/usr/bin/env bash
# check-changelog-version.sh — pre-merge guard: a package.json version bump must
# ship with its CHANGELOG.md section in the same change.
#
# The release flow (release-prep.sh, run via the `release` label) bumps
# package.json AND rolls the pending changelog.d/ fragments into a
# `## [version]` section in one commit, so the two never drift. A hand-written
# bump that skips that step leaves CHANGELOG.md without the section; that only
# surfaces post-merge in tag-release.sh — AFTER the immutable vX.Y.Z tag is
# already pushed, where it is no longer cleanly fixable. This check moves the
# failure pre-merge by failing loudly the moment the version moves without a
# matching changelog section.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

read_version() { node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(0, "utf8")).version)'; }

CURRENT_VERSION=$(read_version <package.json)
if ! [[ "$CURRENT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: package.json version is not strict X.Y.Z: $CURRENT_VERSION" >&2
  exit 1
fi

# Resolve the baseline version to diff against. On a PR, BASE_SHA is the merge
# target commit (already in history under `fetch-depth: 0`, so no network or
# credentials); on a push, fall back to the previous commit (mirrors
# tag-release.sh). With no baseline (e.g. the repo's first commit), there is no
# bump to guard, so the section is not yet required.
if [[ -n "${BASE_SHA:-}" ]]; then
  BASE_VERSION=$(git show "$BASE_SHA:package.json" | read_version)
elif PREV=$(git show "HEAD~1:package.json" 2>/dev/null); then
  BASE_VERSION=$(printf '%s' "$PREV" | read_version)
else
  BASE_VERSION=""
fi

if [[ "$CURRENT_VERSION" == "$BASE_VERSION" ]]; then
  echo "package.json version unchanged ($CURRENT_VERSION). No changelog section required."
  exit 0
fi

echo "package.json version changed: ${BASE_VERSION:-<none>} -> $CURRENT_VERSION"

# Reuse the exact section-extraction logic the release uses, so this guard and
# the post-merge notes step agree on what counts as a present section. It fails
# loudly on its own when the section is missing or empty; add the actionable
# remediation pointing at the right release path.
if ! "$SCRIPT_DIR/changelog-notes.sh" "$CURRENT_VERSION" >/dev/null; then
  echo "Error: package.json was bumped to $CURRENT_VERSION but CHANGELOG.md has no [$CURRENT_VERSION] section." >&2
  echo "Don't hand-bump package.json: label the PR 'release' so release-prep.sh rolls the changelog.d/ fragments and the bump together." >&2
  exit 1
fi
echo "CHANGELOG.md has a [$CURRENT_VERSION] section. OK."
