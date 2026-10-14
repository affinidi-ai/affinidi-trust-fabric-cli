#!/usr/bin/env bash
# Replaces the notes of a published GitHub Release with that version's section
# of CHANGELOG.md without its heading, followed by the people whose first pull
# request is in it and a link to all changes since the previous release.
# Takes the tag, for example `scripts/release-notes.sh v0.2.0`, and needs
# GH_TOKEN and GH_REPO. Run by .github/workflows/release.yaml in a full clone,
# so the tags and history are there.
#
# When CHANGELOG.md at the tag has no section for the version, the notes GitHub
# generated are left as they are and a warning is shown.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <tag>" >&2
  exit 2
fi
tag="$1"
if ! [[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "error: the tag must look like v1.2.3, got '${tag}'" >&2
  exit 1
fi
version="${tag#v}"

if ! changelog="$(git show "${tag}:CHANGELOG.md")"; then
  echo "error: could not read CHANGELOG.md at ${tag}" >&2
  exit 1
fi
section="$(printf '%s\n' "${changelog}" | "$(dirname "${BASH_SOURCE[0]}")/changelog-section.sh" "${version}")"
if [ -z "${section}" ]; then
  echo "::warning::CHANGELOG.md at ${tag} has no section for ${version}, so the release keeps the notes GitHub generated"
  exit 0
fi

previous_tag="$(git describe --tags --abbrev=0 --match 'v*' "${tag}^" 2>/dev/null || true)"
generate_args=(--method POST "repos/{owner}/{repo}/releases/generate-notes" -f "tag_name=${tag}")
if [ -n "${previous_tag}" ]; then
  generate_args+=(-f "previous_tag_name=${previous_tag}")
fi
generated="$(gh api "${generate_args[@]}" --jq .body)"

# GitHub lists each person whose first pull request is in the release as
# `* @<user> made their first contribution in <url>`. Each becomes
# `- @<user> in [#<number>](<url>)`, and GitHub shows the people mentioned as
# avatars under the notes. Bots show up as `@name[bot]` or `@app/name` and are
# dropped, as is any line whose user or pull request link looks unexpected.
pull_url="${GITHUB_SERVER_URL:-https://github.com}/${GH_REPO}/pull/"
new_contributors="$(
  printf '%s\n' "${generated}" \
    | sed -nE 's/^\* @([^ ]+) made their first contribution in (https:\/\/[^ ]+)$/\1 \2/p' \
    | awk -v pull_url="${pull_url}" '
        $1 ~ /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/ &&
        index($2, pull_url) == 1 &&
        substr($2, length(pull_url) + 1) ~ /^[0-9]+$/ &&
        !seen[tolower($1)]++ {
          printf "- @%s in [#%s](%s)\n", $1, substr($2, length(pull_url) + 1), $2
        }
      '
)"

notes_file="$(mktemp)"
trap 'rm -f "${notes_file}"' EXIT
{
  printf '%s\n' "${section}"
  if [ -n "${new_contributors}" ]; then
    printf '\n### 🎉 First-time contributors\n\n%s\n' "${new_contributors}"
  fi
  if [ -n "${previous_tag}" ]; then
    printf '\n**Full changelog**: %s/%s/compare/%s...%s\n' \
      "${GITHUB_SERVER_URL:-https://github.com}" "${GH_REPO}" "${previous_tag}" "${tag}"
  fi
} > "${notes_file}"

gh release edit "${tag}" --notes-file "${notes_file}"
echo "Updated the notes of release ${tag}"
