#!/usr/bin/env bash
# Exit 0 iff the diff between $BASE_SHA and $HEAD_SHA touches a file mutation
# testing depends on (the mutated sources, the tests that kill mutants, the
# Stryker config, package.json, or this workflow). Exit 1 means "nothing
# mutation-relevant changed, skip the expensive run".
#
# On a push to main (or any event without a usable base) we cannot cheaply diff,
# so we fail OPEN (exit 0) and let the full run decide — never skip a real gate
# on a missing base.

set -euo pipefail

base="${BASE_SHA:-}"
head="${HEAD_SHA:-}"

if [[ -z "$base" || -z "$head" ]]; then
  echo "No base/head SHA provided; running mutation testing (fail open)."
  exit 0
fi

# A shallow checkout may lack the base commit; deepen until the diff resolves.
if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
  git fetch --no-tags --depth=1 origin "$base" 2>/dev/null || true
fi
if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
  echo "Base commit $base not fetchable; running mutation testing (fail open)."
  exit 0
fi

changed=$(git diff --name-only "$base" "$head" --)

printf '%s\n' "$changed" | grep -qE \
  '^(src/.*\.mjs|test/.*\.mjs|stryker\.conf\.json|package\.json|\.github/(workflows/mutation\.yaml|scripts/mutation-changed\.sh))$'
