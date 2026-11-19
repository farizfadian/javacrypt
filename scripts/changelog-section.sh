#!/usr/bin/env bash
# Prints the CHANGELOG.md section of one released version, for use as the body
# of its GitHub Release.
#
# The section must exist with a release date, as "## [1.0.0] - 2026-11-19".
# When releasing, rename "## [Unreleased]" to that form (and update the link
# definitions at the bottom of the file).
#
# Usage: scripts/changelog-section.sh <version> [changelog-file]
set -euo pipefail

version="${1:?usage: changelog-section.sh <version> [changelog-file]}"
file="${2:-CHANGELOG.md}"

header="$(grep -nE "^## \[${version//./\\.}\] - [0-9]{4}-[0-9]{2}-[0-9]{2}\$" "$file" || true)"
if [ -z "$header" ]; then
  echo "error: $file has no section \"## [$version] - YYYY-MM-DD\"." >&2
  echo "       Rename \"## [Unreleased]\" to it before tagging v$version." >&2
  exit 1
fi
start="${header%%:*}"

# Everything after the header, up to the next "## [" heading or the link definitions.
body="$(awk -v start="$start" '
  NR <= start { next }
  /^## \[/ { exit }
  /^\[[^]]+\]: / { exit }
  { print }
' "$file")"

if [ -z "$(printf '%s' "$body" | tr -d '[:space:]')" ]; then
  echo "error: the section for $version in $file is empty." >&2
  exit 1
fi

# Without leading and trailing blank lines.
printf '%s\n' "$body" | awk '
  NF { seen = 1 }
  seen { lines[++n] = $0 }
  END { while (n > 0 && lines[n] ~ /^[[:space:]]*$/) n--; for (i = 1; i <= n; i++) print lines[i] }
'
