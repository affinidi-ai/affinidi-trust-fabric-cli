#!/usr/bin/env bash
# Commits the prepared release files to a branch on GitHub, for example
# `scripts/commit-release.sh main 0.2.0`. semantic-release runs this while it
# prepares a release, after CHANGELOG.md has the new notes and
# scripts/set-version.sh has set the version in Cargo.toml and Cargo.lock.
#
# The three files are committed as `chore: release v<version>` with the
# GraphQL mutation createCommitOnBranch, using the release bot's token in
# GH_TOKEN, so GitHub signs the commit and shows it as verified. GitHub only
# makes the commit on top of the checked out commit; if the branch has moved
# on, it refuses and nothing is released. The checked out branch is then moved
# to the new commit, so semantic-release tags that commit.
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN must hold the release bot token}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must name the repository as owner/name}"

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <branch> <X.Y.Z>" >&2
  exit 2
fi
branch="$1"
version="$2"
if ! [[ "${version}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "error: the version must look like 1.2.3, got '${version}'" >&2
  exit 1
fi
if ! git check-ref-format --branch "${branch}" > /dev/null 2>&1; then
  echo "error: '${branch}' isn't a valid branch name" >&2
  exit 1
fi
if ! [[ "${GITHUB_REPOSITORY}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "error: GITHUB_REPOSITORY must look like owner/name, got '${GITHUB_REPOSITORY}'" >&2
  exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

files=(CHANGELOG.md Cargo.toml Cargo.lock)
headline="chore: release v${version}"
head="$(git rev-parse HEAD)"

# The commit must hold exactly what was prepared here: every release file
# changed and no other tracked file.
for file in "${files[@]}"; do
  if git diff --quiet HEAD -- "${file}"; then
    echo "error: ${file} has no changes to release" >&2
    exit 1
  fi
done
other_changes="$(git status --porcelain --untracked-files=no -- . \
  ':(exclude)CHANGELOG.md' ':(exclude)Cargo.toml' ':(exclude)Cargo.lock')"
if [ -n "${other_changes}" ]; then
  echo "error: files other than ${files[*]} changed:" >&2
  echo "${other_changes}" >&2
  exit 1
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

# The contents go through files rather than arguments, because Cargo.lock in
# base64 can be longer than one command line argument may be.
for file in "${files[@]}"; do
  base64 < "${file}" | tr -d '\n' > "${work_dir}/${file}.b64"
done
# shellcheck disable=SC2016 # $input is a GraphQL variable, not a shell one.
mutation='mutation($input: CreateCommitOnBranchInput!) {
  createCommitOnBranch(input: $input) { commit { oid } }
}'
jq --null-input \
  --arg query "${mutation}" \
  --arg repository "${GITHUB_REPOSITORY}" \
  --arg branch "${branch}" \
  --arg head "${head}" \
  --arg headline "${headline}" \
  --rawfile changelog "${work_dir}/CHANGELOG.md.b64" \
  --rawfile manifest "${work_dir}/Cargo.toml.b64" \
  --rawfile lockfile "${work_dir}/Cargo.lock.b64" \
  '{
    query: $query,
    variables: {
      input: {
        branch: { repositoryNameWithOwner: $repository, branchName: $branch },
        expectedHeadOid: $head,
        message: { headline: $headline },
        fileChanges: {
          additions: [
            { path: "CHANGELOG.md", contents: $changelog },
            { path: "Cargo.toml", contents: $manifest },
            { path: "Cargo.lock", contents: $lockfile }
          ]
        }
      }
    }
  }' > "${work_dir}/request.json"

commit="$(gh api graphql --input "${work_dir}/request.json" --jq '.data.createCommitOnBranch.commit.oid')"
if ! [[ "${commit}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "error: GitHub didn't return the release commit, got '${commit}'" >&2
  exit 1
fi
echo "Committed ${headline} to ${branch} as ${commit}"

# The branch is fetched rather than the commit, because a server only has to
# serve commits that a branch or tag points to. The new commit is in the
# fetched history even if the branch has moved on again.
if ! git fetch --quiet --no-tags origin "refs/heads/${branch}"; then
  echo "error: could not fetch ${commit}; it is on ${branch} without a tag, so run the version workflow again to tag it" >&2
  exit 1
fi
if ! git cat-file -e "${commit}^{commit}" 2> /dev/null || [ "$(git rev-parse "${commit}^")" != "${head}" ]; then
  echo "error: ${commit} isn't a commit on top of ${head} in ${branch}" >&2
  exit 1
fi
git reset --quiet "${commit}"
if ! git diff --quiet -- "${files[@]}"; then
  echo "error: ${commit} doesn't hold the prepared ${files[*]}" >&2
  exit 1
fi
