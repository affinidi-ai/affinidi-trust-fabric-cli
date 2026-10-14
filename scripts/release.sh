#!/usr/bin/env bash
# Makes the next release from the checked out commit of `main`. Run by
# .github/workflows/version.yaml after `npm ci` in .github/release, with the
# release bot's token in GH_TOKEN and its app slug in APP_SLUG. Any arguments
# are passed on to semantic-release.
#
# Before semantic-release runs, two cases get a tag pushed first:
# - No `v*` tag is reachable yet: the version already in Cargo.toml is tagged
#   at the commit that added its section to CHANGELOG.md, so later commits are
#   left for semantic-release to release.
# - A `chore: release vX.Y.Z` commit from the bot has no tag, because the run
#   failed after the commit reached `main`: that commit is tagged, so
#   semantic-release doesn't try to make vX.Y.Z again.
# semantic-release then works out the next version from the commit titles
# since the last tag, has scripts/commit-release.sh commit
# `chore: release v<version>` to `main` through the GitHub API, which signs it,
# and pushes the tag on that commit. Every tag push starts
# .github/workflows/release.yaml.
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN must hold the release bot token}"
: "${APP_SLUG:?APP_SLUG must hold the release bot app slug}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

# GitHub makes the release commit as the app's bot user, whose noreply email is
# how an untagged release commit is found below. The tags this script makes and
# semantic-release's git notes are made locally with the same name and email,
# so they show as the bot's too. semantic-release sets its own author unless
# these variables are set, so git config alone isn't enough.
if ! [[ "${APP_SLUG}" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
  echo "error: unexpected app slug '${APP_SLUG}'" >&2
  exit 1
fi
bot_name="${APP_SLUG}[bot]"
bot_id="$(gh api "users/${bot_name}" --jq .id)"
if ! [[ "${bot_id}" =~ ^[0-9]+$ ]]; then
  echo "error: could not find the user id of ${bot_name}" >&2
  exit 1
fi
export GIT_AUTHOR_NAME="${bot_name}"
export GIT_AUTHOR_EMAIL="${bot_id}+${bot_name}@users.noreply.github.com"
export GIT_COMMITTER_NAME="${GIT_AUTHOR_NAME}"
export GIT_COMMITTER_EMAIL="${GIT_AUTHOR_EMAIL}"

semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

# Prints the [package] version in Cargo.toml at the given commit.
package_version() {
  git show "$1:Cargo.toml" | awk '
    /^\[/ { in_package = ($0 == "[package]") }
    in_package && /^version[ \t]*=/ {
      sub(/^version[ \t]*=[ \t]*"/, ""); sub(/".*$/, ""); print; exit
    }
  '
}

# Tags the commit and pushes the tag. The tag push starts the release workflow.
push_tag() {
  local tag="$1" commit="$2"
  git tag --annotate --message "${tag}" "${tag}" "${commit}"
  git push origin "refs/tags/${tag}"
}

if [ -z "$(git tag --list 'v*' --merged HEAD)" ]; then
  version="$(package_version HEAD)"
  if ! [[ "${version}" =~ ${semver} ]]; then
    echo "error: Cargo.toml has no plain X.Y.Z package version, got '${version}'" >&2
    exit 1
  fi
  # The version line itself may be older than the release it stands for, so
  # the release is the commit that added the version's CHANGELOG.md section.
  # -S only matches commits that change how often the exact text
  # `## [X.Y.Z]` appears, so a later edit to that heading, such as its date,
  # doesn't count.
  commit="$(git log -1 --format=%H -S "## [${version}]" HEAD -- CHANGELOG.md)"
  if [ -z "${commit}" ] || [ "$(package_version "${commit}")" != "${version}" ]; then
    echo "error: no commit adds a CHANGELOG.md section for ${version} while Cargo.toml is at ${version}" >&2
    exit 1
  fi
  echo "No v* tag yet, so tagging the current version v${version} at $(git rev-parse --short "${commit}")"
  push_tag "v${version}" "${commit}"
else
  last_tag="$(git describe --tags --abbrev=0 --match 'v*' HEAD)"
  # Only the bot's own release commits count; a pull request title that looks
  # like one is authored by whoever opened the pull request.
  release_commit="$(git log --fixed-strings --author="<${GIT_AUTHOR_EMAIL}>" --format='%H %s' "${last_tag}..HEAD" \
    | grep -E -m 1 '^[0-9a-f]+ chore: release v[^ ]+$' || true)"
  if [ -n "${release_commit}" ]; then
    commit="${release_commit%% *}"
    version="${release_commit##* v}"
    if ! [[ "${version}" =~ ${semver} ]] || [ "$(package_version "${commit}")" != "${version}" ]; then
      echo "error: release commit $(git rev-parse --short "${commit}") doesn't set Cargo.toml to '${version}'" >&2
      exit 1
    fi
    echo "Release commit $(git rev-parse --short "${commit}") has no tag, so tagging it v${version}"
    push_tag "v${version}" "${commit}"
  fi
fi

exec "${root}/.github/release/node_modules/.bin/semantic-release" \
  --extends "${root}/.github/release/release.config.mjs" "$@"
