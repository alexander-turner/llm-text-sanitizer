#!/usr/bin/env bash
# Set python/pyproject.toml's [project] version to $1 in the WORKING TREE only
# (never committed) for a release build. Mirrors how the npm flow injects the
# version into package.json: the committed value is a frozen 0.0.0 placeholder,
# and PyPI + the git tag are the source of truth. Fails loudly if the version
# line is absent or unchanged, so a release never silently ships 0.0.0.
#
# Usage: set-pyproject-version.sh <version>

set -euo pipefail

version="${1:?usage: set-pyproject-version.sh <version>}"
file="python/pyproject.toml"

# Replace only the FIRST `version = "..."` line (the [project] version). The
# `done` flag stops after the first match so nothing else can be rewritten.
awk -v v="$version" '
  !done && /^version = "[^"]*"$/ {
    print "version = \"" v "\""
    done = 1
    next
  }
  { print }
' "$file" >"$file.tmp"
mv "$file.tmp" "$file"

if ! grep -qxF "version = \"$version\"" "$file"; then
  echo "::error::failed to set version to $version in $file" >&2
  exit 1
fi
echo "Set $file version to $version (working tree only)."
