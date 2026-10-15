#!/usr/bin/env bash
# Opens the pull request that moves the fabric cask in the Homebrew tap to a
# release, for example `scripts/open-tap-pr.sh 0.2.0 dist/fabric.rb`, with the
# cask scripts/homebrew-cask.sh printed. Run by
# .github/workflows/homebrew-tap.yaml after a release, with a release bot token
# in GH_TOKEN that can only change the tap's contents and pull requests.
# TAP_REPOSITORY names the tap as owner/name, affinidi-ai/homebrew-tap unless
# set. RELEASE_RUN_URL, when set, is the release workflow run the pull request
# links to.
#
# The cask goes to Casks/fabric.rb on a branch `fabric-<version>`, made from
# the tap's main if it doesn't exist yet, as one commit
# `chore(cask): fabric <version>` made with the GraphQL mutation
# createCommitOnBranch, so GitHub signs it. The pull request to main has the
# same title. A step that is already done is skipped: nothing is committed
# when the branch already holds this cask, and no pull request is opened when
# one is open for the branch, so a re-run is safe. When main already holds
# this cask or a newer version, nothing is done at all, so a retry after the
# merge or a re-run of an old release opens no pull request. Nothing is
# pushed to main; a CODEOWNER of the tap merges the pull request.
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN must hold the release bot token}"
tap="${TAP_REPOSITORY:-affinidi-ai/homebrew-tap}"

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <X.Y.Z> <cask file>" >&2
  exit 2
fi
version="$1"
cask="$2"
if ! [[ "${version}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "error: the version must look like 1.2.3, got '${version}'" >&2
  exit 1
fi
if [ ! -s "${cask}" ]; then
  echo "error: ${cask} is missing or empty" >&2
  exit 1
fi
if ! [[ "${tap}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "error: TAP_REPOSITORY must look like owner/name, got '${tap}'" >&2
  exit 1
fi
if [ -n "${RELEASE_RUN_URL:-}" ] &&
  ! [[ "${RELEASE_RUN_URL}" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+$ ]]; then
  echo "error: RELEASE_RUN_URL must be a GitHub Actions run URL, got '${RELEASE_RUN_URL}'" >&2
  exit 1
fi

branch="fabric-${version}"
cask_path="Casks/fabric.rb"
title="chore(cask): fabric ${version}"
release_url="https://github.com/affinidi-ai/affinidi-trust-fabric-cli/releases/tag/v${version}"

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

# Sends one GraphQL request, built by jq from the given arguments, and prints
# the response, or the value the second argument picks from it.
graphql() {
  local filter="$1" pick="$2"
  shift 2
  jq --null-input "$@" "${filter}" > "${work_dir}/request.json"
  gh api graphql --input "${work_dir}/request.json" --jq "${pick}"
}

# Everything already done for this version, in one request: main's head and
# cask, the branch's head and open pull request, and the cask on the branch.
# shellcheck disable=SC2016 # $owner and the rest are GraphQL variables, not shell ones.
state_query='query($owner: String!, $name: String!, $base: String!, $baseFile: String!, $branch: String!, $file: String!) {
  repository(owner: $owner, name: $name) {
    id
    base: ref(qualifiedName: $base) { target { oid } }
    baseCask: object(expression: $baseFile) { ... on Blob { text } }
    branch: ref(qualifiedName: $branch) {
      target { oid }
      associatedPullRequests(states: OPEN, first: 1) { nodes { url } }
    }
    cask: object(expression: $file) { ... on Blob { text } }
  }
}'
# shellcheck disable=SC2016 # $query and the rest are jq variables, not shell ones.
graphql '{ query: $query, variables: { owner: $owner, name: $name, base: $base, baseFile: $baseFile, branch: $branch, file: $file } }' . \
  --arg query "${state_query}" \
  --arg owner "${tap%%/*}" \
  --arg name "${tap#*/}" \
  --arg base "refs/heads/main" \
  --arg baseFile "main:${cask_path}" \
  --arg branch "refs/heads/${branch}" \
  --arg file "${branch}:${cask_path}" > "${work_dir}/state.json"

state() {
  jq --raw-output ".data.repository | $1 // empty" "${work_dir}/state.json"
}
repository_id="$(state .id)"
head="$(state .branch.target.oid)"
pull_request="$(state '.branch.associatedPullRequests.nodes[0].url')"
if [ -z "${repository_id}" ]; then
  echo "error: GitHub didn't return ${tap}" >&2
  exit 1
fi

# Main holding this cask means its pull request was merged, and main holding
# a newer version means this is an old release: either way there is nothing
# to propose. The same version with other hashes, from a re-run of the macOS
# jobs, still gets a pull request.
jq --join-output '.data.repository.baseCask.text // empty' "${work_dir}/state.json" > "${work_dir}/main.rb"
if cmp -s "${work_dir}/main.rb" "${cask}"; then
  echo "::notice::main of ${tap} already holds this ${cask_path}, so no pull request is opened"
  exit 0
fi
main_version="$(sed -n 's/^  version "\(.*\)"$/\1/p' "${work_dir}/main.rb")"
if [ -n "${main_version}" ]; then
  if ! [[ "${main_version}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "error: ${cask_path} on main of ${tap} has the version '${main_version}', not one like 1.2.3" >&2
    exit 1
  fi
  if [ "${main_version}" != "${version}" ] &&
    [ "$(printf '%s\n%s\n' "${main_version}" "${version}" | sort -V | tail -n 1)" = "${main_version}" ]; then
    echo "::notice::main of ${tap} already holds fabric ${main_version}, newer than ${version}, so no pull request is opened"
    exit 0
  fi
fi

if [ -z "${head}" ]; then
  head="$(state .base.target.oid)"
  if ! [[ "${head}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "error: ${tap} has no main branch to start ${branch} from" >&2
    exit 1
  fi
  # shellcheck disable=SC2016 # $input and the rest are GraphQL and jq variables, not shell ones.
  graphql '{ query: $query, variables: { input: { repositoryId: $id, name: $ref, oid: $oid } } }' \
    .data.createRef.ref.name \
    --arg query 'mutation($input: CreateRefInput!) { createRef(input: $input) { ref { name } } }' \
    --arg id "${repository_id}" \
    --arg ref "refs/heads/${branch}" \
    --arg oid "${head}" > /dev/null
  echo "Created ${branch} on ${tap} at ${head}"
fi

jq --join-output '.data.repository.cask.text // empty' "${work_dir}/state.json" > "${work_dir}/current.rb"
if cmp -s "${work_dir}/current.rb" "${cask}"; then
  echo "${branch} already holds this ${cask_path}"
else
  base64 < "${cask}" | tr -d '\n' > "${work_dir}/cask.b64"
  # shellcheck disable=SC2016 # $input and the rest are GraphQL and jq variables, not shell ones.
  commit="$(graphql '{
      query: $query,
      variables: {
        input: {
          branch: { repositoryNameWithOwner: $repository, branchName: $branch },
          expectedHeadOid: $head,
          message: { headline: $headline },
          fileChanges: { additions: [{ path: $path, contents: $contents }] }
        }
      }
    }' .data.createCommitOnBranch.commit.oid \
    --arg query 'mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid } } }' \
    --arg repository "${tap}" \
    --arg branch "${branch}" \
    --arg head "${head}" \
    --arg headline "${title}" \
    --arg path "${cask_path}" \
    --rawfile contents "${work_dir}/cask.b64")"
  if ! [[ "${commit}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "error: GitHub didn't return the cask commit, got '${commit}'" >&2
    exit 1
  fi
  echo "Committed ${title} to ${branch} as ${commit}"
fi

if [ -n "${pull_request}" ]; then
  echo "Pull request already open: ${pull_request}"
  exit 0
fi
if [ -n "${RELEASE_RUN_URL:-}" ]; then
  release_run="[release workflow run](${RELEASE_RUN_URL})"
else
  release_run="\`release\` workflow run of v${version}"
fi
cat > "${work_dir}/body.md" << EOF
Moves the fabric cask to the release [v${version}](${release_url}). Opened by the homebrew-tap workflow of affinidi-ai/affinidi-trust-fabric-cli.

Before approving, check that:

- the title and \`version\` are ${version}, from the tag v${version} that was released, and the ${release_run} passed;
- \`url\` is \`https://github.com/affinidi-ai/affinidi-trust-fabric-cli/releases/download/v#{version}/fabric-#{version}-#{arch}-apple-darwin.tar.gz\`, the versioned release archive;
- both \`sha256\` values match the release's \`SHA256SUMS\`;
- the cask has no \`preflight\`, \`postflight\`, \`system_command\`, \`xattr\` or quarantine handling;
- the \`cask\` check on this pull request passed.
EOF
# shellcheck disable=SC2016 # $input and the rest are GraphQL and jq variables, not shell ones.
pull_request="$(graphql '{
    query: $query,
    variables: { input: { repositoryId: $id, baseRefName: "main", headRefName: $branch, title: $title, body: $body } }
  }' .data.createPullRequest.pullRequest.url \
  --arg query 'mutation($input: CreatePullRequestInput!) { createPullRequest(input: $input) { pullRequest { url } } }' \
  --arg id "${repository_id}" \
  --arg branch "${branch}" \
  --arg title "${title}" \
  --rawfile body "${work_dir}/body.md")"
echo "Opened ${pull_request}"
