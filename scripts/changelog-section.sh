#!/usr/bin/env bash
# Prints the body of one version's section of a changelog read from standard
# input, without its heading. Takes the version, for example
# `scripts/changelog-section.sh 0.2.0 < CHANGELOG.md`. Prints nothing when the
# changelog has no section for the version. Used by scripts/release-notes.sh.
#
# A section starts at a `## ` heading for the version, either `## [0.2.0](...)`
# as semantic-release writes it or `## [0.1.0] - date`, and runs up to the next
# `## ` heading. Blank lines around the body are dropped.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <version> < CHANGELOG.md" >&2
  exit 2
fi

awk -v version="$1" '
  /^## / {
    if (in_section) exit
    heading = substr($0, 4)
    sub(/^\[/, "", heading)
    after = substr(heading, length(version) + 1, 1)
    if (index(heading, version) == 1 && (after == "" || after == "]" || after == " " || after == "(")) {
      in_section = 1
    }
    next
  }
  in_section && !started && /^[ \t]*$/ { next }
  in_section {
    started = 1
    if (/^[ \t]*$/) { blank_lines++; next }
    for (; blank_lines > 0; blank_lines--) print ""
    print
  }
'
