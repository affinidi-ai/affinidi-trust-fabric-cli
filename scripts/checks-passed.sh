#!/usr/bin/env bash
# Stops unless the checks workflow passed on a push of the given commit to
# main, for example `scripts/checks-passed.sh "${GITHUB_SHA}"`. Run by
# .github/workflows/version.yaml when someone runs it by hand, before it gets
# the release bot's token. main doesn't need the checks to pass before a
# merge, so a commit whose checks failed can be on main, and a run by hand
# would otherwise release it.
#
# Only the newest checks run for a push of that commit to main counts, so a
# re-run that passed counts, and an older pass doesn't hide a newer failure.
# The daily run, a run by hand, and a pull request's run of the same commit
# don't count. If GitHub can't be asked, the script stops too.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <commit sha>" >&2
  exit 2
fi
sha="$1"
if ! [[ "${sha}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "error: ${sha} is not a full commit sha" >&2
  exit 1
fi
: "${GITHUB_REPOSITORY:?}"

# GitHub filters by the checks workflow's file, the commit, the push event and
# main; the fields it answers with are checked again below.
if ! run="$(gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/checks.yaml/runs?branch=main&event=push&head_sha=${sha}&per_page=100" \
  --jq '.workflow_runs | max_by(.run_number) // empty
    | [.head_sha, .head_branch, .event, .head_repository.full_name, .status, (.conclusion // "none"), .html_url]
    | @tsv')"; then
  echo "::error::Couldn't ask GitHub for the checks runs of ${sha}, so nothing is released"
  exit 1
fi

if [ -z "${run}" ]; then
  echo "::error::The checks workflow has no run for the push of ${sha} to main, so nothing is released. Once the checks pass on that push, the release follows by itself; run version by hand only if it doesn't start"
  exit 1
fi
IFS=$'\t' read -r run_sha run_branch run_event run_repo status conclusion url <<< "${run}"
if [ "${run_sha}" != "${sha}" ] || [ "${run_branch}" != main ] || [ "${run_event}" != push ] || [ "${run_repo}" != "${GITHUB_REPOSITORY}" ]; then
  echo "::error::GitHub answered with a checks run of ${run_sha} on ${run_branch} by ${run_event} in ${run_repo}, not of the push of ${sha} to main, so nothing is released: ${url}"
  exit 1
fi
if [ "${status}" != completed ]; then
  echo "::error::The checks on ${sha} are still running (${status}), so nothing is released. Once they pass, the release follows by itself; run version by hand only if it doesn't start: ${url}"
  exit 1
fi
if [ "${conclusion}" != success ]; then
  echo "::error::The checks on ${sha} ended with ${conclusion}, so nothing is released. Fix main, or re-run that push's checks if the failure was a fluke. Once they pass, the release follows by itself; run version by hand only if it doesn't start: ${url}"
  exit 1
fi
echo "The checks passed on ${sha}: ${url}"
