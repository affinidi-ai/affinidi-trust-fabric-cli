#!/usr/bin/env bash
# Checks the release scripts without a release or the network:
# scripts/set-version.sh changes exactly the two version lines in a copy of
# Cargo.toml and Cargo.lock, scripts/changelog-section.sh finds the right
# section of scripts/testdata/CHANGELOG.md, and scripts/commit-release.sh
# commits the release files on top of the checked out commit and moves HEAD to
# that commit, or changes nothing. scripts/macos-sums.sh adds the macOS
# archives to SHA256SUMS once, even on a re-run, scripts/release-sums.sh
# rebuilds a release's SHA256SUMS only when it is missing,
# scripts/homebrew-cask.sh renders the cask from a SHA256SUMS,
# scripts/open-tap-pr.sh opens the tap pull request once, even on a re-run,
# when the tap's main holds an older version, none once main holds the cask
# or a newer one, and stops when main's version isn't X.Y.Z, and
# scripts/sign-macos.sh stops on a bad argument or setting before it needs a
# Mac. Run by .github/workflows/checks.yaml; the working tree is never changed.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
testdata="${root}/scripts/testdata"
work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT
failures=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

# set-version.sh edits the files next to its own directory, so it runs from a
# copy laid out like the repository.
mkdir -p "${work_dir}/repo/scripts"
cp "${root}/Cargo.toml" "${root}/Cargo.lock" "${work_dir}/repo/"
cp "${root}/scripts/set-version.sh" "${work_dir}/repo/scripts/"
"${work_dir}/repo/scripts/set-version.sh" 9.9.9 > /dev/null
version_diff="$(
  for file in Cargo.toml Cargo.lock; do
    diff "${root}/${file}" "${work_dir}/repo/${file}" || true
  done
)"
# Prints a key of the [package] section of Cargo.toml.
package_field() {
  awk -v key="$1" '
    /^\[/ { in_package = ($0 == "[package]") }
    in_package && $0 ~ "^" key "[ \t]*=" {
      sub(/^[^=]*=[ \t]*"/, ""); sub(/".*$/, ""); print; exit
    }
  ' "${root}/Cargo.toml"
}
# The removed lines must be this package's current version, and this
# package's own Cargo.lock entry must hold the new one, so a bump of another
# package's entry fails too, even one at the same version.
current_version="$(package_field version)"
package_name="$(package_field name)"
removed_lines="$(grep -c '^<' <<< "${version_diff}" || true)"
old_version_lines="$(grep -cxF "< version = \"${current_version}\"" <<< "${version_diff}" || true)"
changed_lines="$(grep -c '^>' <<< "${version_diff}" || true)"
new_version_lines="$(grep -cx '> version = "9.9.9"' <<< "${version_diff}" || true)"
if [ "${removed_lines}" != "2" ] || [ "${old_version_lines}" != "2" ] || [ "${changed_lines}" != "2" ] || [ "${new_version_lines}" != "2" ]; then
  fail "set-version.sh 9.9.9 replaced ${removed_lines} lines (${old_version_lines} of them version ${current_version}) with ${changed_lines} (${new_version_lines} of them version 9.9.9); expected 2 and 2 each"
fi
lock_version="$(grep -A1 -xF "name = \"${package_name}\"" "${work_dir}/repo/Cargo.lock" | sed -n 2p)"
if [ "${lock_version}" != 'version = "9.9.9"' ]; then
  fail "set-version.sh 9.9.9 left the Cargo.lock entry of ${package_name} at: ${lock_version}"
fi

check_section() {
  local version="$1" expected="$2" actual
  actual="$("${root}/scripts/changelog-section.sh" "${version}" < "${testdata}/CHANGELOG.md")"
  if [ "${actual}" != "${expected}" ]; then
    fail "section ${version} of scripts/testdata/CHANGELOG.md:"
    diff <(printf '%s\n' "${expected}") <(printf '%s\n' "${actual}") >&2 || true
  fi
}
check_section 0.2.1 "$(cat "${testdata}/section-0.2.1.md")"
check_section 0.1.0 "$(cat "${testdata}/section-0.1.0.md")"
check_section 9.9.9 ""

# commit-release.sh runs in a repository laid out like this one, whose origin
# is a local bare repository. scripts/testdata/bin/gh stands in for GitHub.
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com
release_repo="${work_dir}/release"
origin="${work_dir}/origin.git"
request="${work_dir}/request.json"

# Makes origin with one commit on main and a clone of it in release_repo
# whose release files are changed the way semantic-release leaves them.
setup_release_repo() {
  rm -rf "${release_repo}" "${origin}" "${request}"
  git init --quiet --bare --initial-branch=main "${origin}"
  mkdir -p "${release_repo}/scripts"
  cp "${root}/Cargo.toml" "${root}/Cargo.lock" "${root}/CHANGELOG.md" "${root}/README.md" "${release_repo}/"
  cp "${root}/scripts/commit-release.sh" "${release_repo}/scripts/"
  git -C "${release_repo}" init --quiet --initial-branch=main
  git -C "${release_repo}" add --all
  git -C "${release_repo}" commit --quiet --message "feat: before the release"
  git -C "${release_repo}" remote add origin "${origin}"
  git -C "${release_repo}" push --quiet origin main
  for file in Cargo.toml Cargo.lock CHANGELOG.md; do
    echo "# release 9.9.9" >> "${release_repo}/${file}"
  done
}

run_commit_release() {
  (
    cd "${release_repo}"
    PATH="${testdata}/bin:${PATH}" GH_TOKEN=test-token GITHUB_REPOSITORY=example/repo \
      FAKE_GH_REQUEST="${request}" FAKE_GH_ORIGIN="${origin}" \
      scripts/commit-release.sh main 9.9.9
  ) > "${work_dir}/commit-release.log" 2>&1
}

setup_release_repo
prepared_head="$(git -C "${release_repo}" rev-parse HEAD)"
if ! run_commit_release; then
  fail "commit-release.sh failed:"
  cat "${work_dir}/commit-release.log" >&2
else
  release_head="$(git -C "${release_repo}" rev-parse HEAD)"
  if [ "${release_head}" != "$(git -C "${origin}" rev-parse main)" ]; then
    fail "commit-release.sh left HEAD at ${release_head}, not at the new commit on main"
  fi
  if [ "$(git -C "${release_repo}" rev-parse HEAD^)" != "${prepared_head}" ]; then
    fail "the release commit's parent isn't the checked out commit ${prepared_head}"
  fi
  if [ "$(git -C "${release_repo}" log -1 --format=%s)" != "chore: release v9.9.9" ]; then
    fail "the release commit's title is '$(git -C "${release_repo}" log -1 --format=%s)'"
  fi
  if [ -n "$(git -C "${release_repo}" status --porcelain --untracked-files=no)" ]; then
    fail "the release commit doesn't hold every prepared change"
  fi
  if [ "$(jq --raw-output .variables.input.expectedHeadOid "${request}")" != "${prepared_head}" ]; then
    fail "commit-release.sh didn't send the checked out commit as expectedHeadOid"
  fi
fi

setup_release_repo
prepared_head="$(git -C "${release_repo}" rev-parse HEAD)"
moved_head="$(git -C "${release_repo}" commit-tree -p HEAD -m "fix: merged meanwhile" "HEAD^{tree}")"
git -C "${release_repo}" push --quiet origin "${moved_head}:refs/heads/main"
if run_commit_release; then
  fail "commit-release.sh committed although main had moved on"
fi
if [ "$(git -C "${release_repo}" rev-parse HEAD)" != "${prepared_head}" ] || [ "$(git -C "${origin}" rev-parse main)" != "${moved_head}" ]; then
  fail "commit-release.sh moved HEAD or main although main had moved on"
fi

setup_release_repo
echo "# not part of a release" >> "${release_repo}/README.md"
if run_commit_release; then
  fail "commit-release.sh committed although README.md changed too"
fi
if [ -e "${request}" ]; then
  fail "commit-release.sh called GitHub although README.md changed too"
fi

# macos-sums.sh adds the macOS archives to a SHA256SUMS holding the Linux ones.
sums_dir="${work_dir}/sums"
mkdir -p "${sums_dir}"
hash_of() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum < "$1" | awk '{ print $1 }'
  else
    shasum -a 256 < "$1" | awk '{ print $1 }'
  fi
}
for target in aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu aarch64-apple-darwin x86_64-apple-darwin; do
  echo "archive for ${target}" > "${sums_dir}/fabric-9.9.9-${target}.tar.gz"
done
linux_sums="$(
  for target in aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu; do
    printf '%s  %s\n' "$(hash_of "${sums_dir}/fabric-9.9.9-${target}.tar.gz")" "fabric-9.9.9-${target}.tar.gz"
  done
)"
mac_archives=("${sums_dir}/fabric-9.9.9-aarch64-apple-darwin.tar.gz" "${sums_dir}/fabric-9.9.9-x86_64-apple-darwin.tar.gz")
expected_sums() {
  for target in aarch64-apple-darwin aarch64-unknown-linux-gnu x86_64-apple-darwin x86_64-unknown-linux-gnu; do
    printf '%s  %s\n' "$(hash_of "${sums_dir}/fabric-9.9.9-${target}.tar.gz")" "fabric-9.9.9-${target}.tar.gz"
  done
}
check_sums() {
  local what="$1" expected
  expected="$(expected_sums)"
  if [ "$(cat "${sums_dir}/SHA256SUMS")" != "${expected}" ]; then
    fail "macos-sums.sh ${what}:"
    diff <(printf '%s\n' "${expected}") "${sums_dir}/SHA256SUMS" >&2 || true
  fi
}

printf '%s\n' "${linux_sums}" > "${sums_dir}/SHA256SUMS"
if ! "${root}/scripts/macos-sums.sh" "${sums_dir}/SHA256SUMS" "${mac_archives[@]}"; then
  fail "macos-sums.sh failed on a SHA256SUMS with only the Linux archives"
fi
check_sums "on a SHA256SUMS with only the Linux archives"

# A re-run, here with a rebuilt archive, replaces the line instead of adding one.
echo "rebuilt archive" > "${mac_archives[0]}"
if ! "${root}/scripts/macos-sums.sh" "${sums_dir}/SHA256SUMS" "${mac_archives[@]}"; then
  fail "macos-sums.sh failed on a re-run"
fi
check_sums "on a re-run"

# Each bad input stops the script and leaves SHA256SUMS as it was.
check_sums_stops() {
  local what="$1" before
  shift
  before="$(cat "${sums_dir}/SHA256SUMS")"
  if "${root}/scripts/macos-sums.sh" "${sums_dir}/SHA256SUMS" "$@" 2> /dev/null; then
    fail "macos-sums.sh passed ${what}"
  fi
  if [ "$(cat "${sums_dir}/SHA256SUMS")" != "${before}" ]; then
    fail "macos-sums.sh changed SHA256SUMS ${what}"
  fi
}
check_sums_stops "with a missing archive" "${mac_archives[0]}" "${sums_dir}/missing.tar.gz"
check_sums_stops "with an archive given twice" "${mac_archives[0]}" "${mac_archives[0]}"
echo "not an archive" > "${sums_dir}/fabric 9.9.9.tar.gz"
check_sums_stops "with an archive name SHA256SUMS can't hold" "${sums_dir}/fabric 9.9.9.tar.gz"
printf '%s\n' "${linux_sums}" "not a checksum line" > "${sums_dir}/SHA256SUMS"
check_sums_stops "with a malformed SHA256SUMS" "${mac_archives[@]}"

# release-sums.sh downloads the release's SHA256SUMS, and rebuilds it from the
# Linux archives only when the release has none. scripts/testdata/release-bin/gh
# serves the files in FAKE_GH_RELEASE as the release.
release_dir="${work_dir}/release"
fetch_dir="${work_dir}/fetched"
mkdir -p "${release_dir}"
for target in aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu; do
  cp "${sums_dir}/fabric-9.9.9-${target}.tar.gz" "${release_dir}/"
done
run_release_sums() {
  rm -rf "${fetch_dir}"
  mkdir -p "${fetch_dir}"
  env "PATH=${testdata}/release-bin:${PATH}" "FAKE_GH_RELEASE=${release_dir}" "$@" \
    "${root}/scripts/release-sums.sh" v9.9.9 "${fetch_dir}" > "${work_dir}/release-sums.log" 2>&1
}
check_release_sums_stops() {
  local what="$1"
  shift
  if run_release_sums "$@"; then
    fail "release-sums.sh passed ${what}"
  elif [ -e "${fetch_dir}/SHA256SUMS" ]; then
    fail "release-sums.sh wrote SHA256SUMS ${what}"
  fi
}

printf '%s\n' "${linux_sums}" "$(hash_of "${mac_archives[0]}")  fabric-9.9.9-aarch64-apple-darwin.tar.gz" \
  > "${release_dir}/SHA256SUMS"
if ! run_release_sums; then
  fail "release-sums.sh failed on a release with a SHA256SUMS:"
  cat "${work_dir}/release-sums.log" >&2
elif ! cmp -s "${release_dir}/SHA256SUMS" "${fetch_dir}/SHA256SUMS"; then
  fail "release-sums.sh didn't download the release's SHA256SUMS as it is"
fi
# A failed download stops the script instead of rebuilding the file.
check_release_sums_stops "when listing the release fails" FAKE_GH_FAIL=view
check_release_sums_stops "when downloading SHA256SUMS fails" FAKE_GH_FAIL=download

rm "${release_dir}/SHA256SUMS"
if ! run_release_sums; then
  fail "release-sums.sh failed on a release with no SHA256SUMS:"
  cat "${work_dir}/release-sums.log" >&2
elif [ "$(cat "${fetch_dir}/SHA256SUMS")" != "${linux_sums}" ]; then
  fail "release-sums.sh rebuilt SHA256SUMS wrong:"
  diff <(printf '%s\n' "${linux_sums}") "${fetch_dir}/SHA256SUMS" >&2 || true
else
  cp "${fetch_dir}/SHA256SUMS" "${sums_dir}/SHA256SUMS"
  if ! "${root}/scripts/macos-sums.sh" "${sums_dir}/SHA256SUMS" "${mac_archives[@]}"; then
    fail "macos-sums.sh failed on a rebuilt SHA256SUMS"
  fi
  check_sums "on a rebuilt SHA256SUMS"
fi
check_release_sums_stops "when downloading a Linux archive fails" FAKE_GH_FAIL=download
rm "${release_dir}/fabric-9.9.9-x86_64-unknown-linux-gnu.tar.gz"
check_release_sums_stops "on a release with no SHA256SUMS and a missing Linux archive"
if "${root}/scripts/release-sums.sh" 9.9.9 "${fetch_dir}" 2> /dev/null; then
  fail "release-sums.sh passed a tag with no leading v"
fi
if "${root}/scripts/release-sums.sh" v9.9.9 2> /dev/null; then
  fail "release-sums.sh passed with no directory"
fi
if "${root}/scripts/release-sums.sh" v9.9.9 "${work_dir}/no-such-dir" 2> /dev/null; then
  fail "release-sums.sh passed a directory that doesn't exist"
fi

# homebrew-cask.sh renders scripts/testdata/fabric-9.9.9.rb from
# scripts/testdata/SHA256SUMS-9.9.9, and stops when a macOS line is missing
# or wrong.
cask_dir="${work_dir}/cask"
mkdir -p "${cask_dir}"
if ! "${root}/scripts/homebrew-cask.sh" 9.9.9 "${testdata}/SHA256SUMS-9.9.9" > "${cask_dir}/fabric.rb"; then
  fail "homebrew-cask.sh failed on scripts/testdata/SHA256SUMS-9.9.9"
elif ! cmp -s "${testdata}/fabric-9.9.9.rb" "${cask_dir}/fabric.rb"; then
  fail "homebrew-cask.sh rendered a different cask:"
  diff "${testdata}/fabric-9.9.9.rb" "${cask_dir}/fabric.rb" >&2 || true
fi
if ! grep -qxF "  desc \"$(package_field description)\"" "${cask_dir}/fabric.rb"; then
  fail "homebrew-cask.sh's desc isn't the description in Cargo.toml"
fi
check_cask_stops() {
  local what="$1" version="$2" sums="$3"
  if "${root}/scripts/homebrew-cask.sh" "${version}" "${sums}" > /dev/null 2>&1; then
    fail "homebrew-cask.sh passed ${what}"
  fi
}
grep -v x86_64-apple-darwin "${testdata}/SHA256SUMS-9.9.9" > "${cask_dir}/no-intel"
check_cask_stops "with no line for the Intel archive" 9.9.9 "${cask_dir}/no-intel"
sed 's/^[0-9a-f]*  \(fabric-9.9.9-aarch64-apple-darwin\)/not-a-sha256  \1/' "${testdata}/SHA256SUMS-9.9.9" \
  > "${cask_dir}/bad-hash"
check_cask_stops "with a line for the Apple silicon archive that isn't a sha256" 9.9.9 "${cask_dir}/bad-hash"
cat "${testdata}/SHA256SUMS-9.9.9" "${testdata}/SHA256SUMS-9.9.9" > "${cask_dir}/twice"
check_cask_stops "with the macOS lines given twice" 9.9.9 "${cask_dir}/twice"
check_cask_stops "with a tag instead of a version" v9.9.9 "${testdata}/SHA256SUMS-9.9.9"
check_cask_stops "with a version that isn't X.Y.Z" 9.9 "${testdata}/SHA256SUMS-9.9.9"
check_cask_stops "with no SHA256SUMS" 9.9.9 "${cask_dir}/missing"

# open-tap-pr.sh runs against a tap that is a local bare repository.
# scripts/testdata/tap-bin/gh stands in for GitHub. new_tap starts the tap
# again with one commit on main, which holds the given cask as
# Casks/fabric.rb when one is given.
tap_origin="${work_dir}/tap.git"
tap_seed="${work_dir}/tap-seed"
tap_pulls="${work_dir}/tap-pulls.jsonl"
tap_calls="${work_dir}/tap-calls"
new_tap() {
  rm -rf "${tap_origin}" "${tap_seed}" "${tap_pulls}"
  git init --quiet --bare --initial-branch=main "${tap_origin}"
  git init --quiet --initial-branch=main "${tap_seed}"
  echo "# tap" > "${tap_seed}/README.md"
  if [ "$#" -eq 1 ]; then
    mkdir -p "${tap_seed}/Casks"
    cp "$1" "${tap_seed}/Casks/fabric.rb"
  fi
  git -C "${tap_seed}" add --all
  git -C "${tap_seed}" commit --quiet --message "feat: the tap"
  git -C "${tap_seed}" push --quiet "${tap_origin}" main
  tap_main="$(git -C "${tap_origin}" rev-parse main)"
}
# Runs open-tap-pr.sh with the given arguments, after the settings that come
# first, for example GH_TOKEN=.
run_open_tap_pr() {
  : > "${tap_calls}"
  (
    export GH_TOKEN=test-token TAP_REPOSITORY=example/homebrew-tap
    export FAKE_GH_ORIGIN="${tap_origin}" FAKE_GH_PULLS="${tap_pulls}" FAKE_GH_CALLS="${tap_calls}"
    while [[ "${1-}" == *=* ]]; do
      export "${1?}"
      shift
    done
    PATH="${testdata}/tap-bin:${PATH}" "${root}/scripts/open-tap-pr.sh" "$@"
  ) > "${work_dir}/open-tap-pr.log" 2>&1
}
# Checks the branch fabric-<version> holds the given cask in one commit on
# top of main per change, and that exactly one pull request is open for it.
check_tap() {
  local what="$1" version="$2" cask="$3" commits="$4" pulls
  local branch="fabric-${version}" title="chore(cask): fabric ${version}"
  if [ "$(git -C "${tap_origin}" rev-parse main)" != "${tap_main}" ]; then
    fail "open-tap-pr.sh ${what} changed main"
  fi
  if [ "$(git -C "${tap_origin}" rev-list --count "${tap_main}..${branch}" 2> /dev/null)" != "${commits}" ]; then
    fail "open-tap-pr.sh ${what} didn't leave ${commits} commit(s) on ${branch} on top of main"
  fi
  if ! cmp -s "${cask}" <(git -C "${tap_origin}" show "${branch}:Casks/fabric.rb" 2> /dev/null); then
    fail "open-tap-pr.sh ${what} didn't leave the cask in Casks/fabric.rb on ${branch}"
  fi
  if [ "$(git -C "${tap_origin}" log -1 --format=%s "${branch}" 2> /dev/null)" != "${title}" ]; then
    fail "open-tap-pr.sh ${what} titled the commit '$(git -C "${tap_origin}" log -1 --format=%s "${branch}" 2> /dev/null)'"
  fi
  pulls="$(jq --compact-output '[.base, .head, .title]' "${tap_pulls}" 2> /dev/null)"
  if [ "${pulls}" != "$(jq --null-input --compact-output --arg branch "${branch}" --arg title "${title}" '["main", $branch, $title]')" ]; then
    fail "open-tap-pr.sh ${what} left these pull requests instead of one to main: ${pulls}"
  fi
}
# Checks a run that should stop before any request left the tap as it was.
check_tap_stops() {
  local what="$1"
  shift
  if run_open_tap_pr "$@"; then
    fail "open-tap-pr.sh passed ${what}"
  elif [ -s "${tap_calls}" ]; then
    fail "open-tap-pr.sh called GitHub ${what}: $(tr '\n' ' ' < "${tap_calls}")"
  fi
}
# Checks a run that finds nothing to do passed after one query, with no
# branch and no pull request.
check_tap_untouched() {
  local what="$1"
  shift
  if ! run_open_tap_pr "$@"; then
    fail "open-tap-pr.sh failed ${what}:"
    cat "${work_dir}/open-tap-pr.log" >&2
  fi
  if [ "$(cat "${tap_calls}")" != query ]; then
    fail "open-tap-pr.sh changed something ${what}: $(tr '\n' ' ' < "${tap_calls}")"
  fi
  if git -C "${tap_origin}" rev-parse --verify --quiet fabric-9.9.9 > /dev/null; then
    fail "open-tap-pr.sh made fabric-9.9.9 ${what}"
  fi
  if [ -s "${tap_pulls}" ]; then
    fail "open-tap-pr.sh opened a pull request ${what}"
  fi
}

new_tap
release_run_url="https://github.com/example/cli/actions/runs/123"
if ! run_open_tap_pr RELEASE_RUN_URL="${release_run_url}" 9.9.9 "${cask_dir}/fabric.rb"; then
  fail "open-tap-pr.sh failed:"
  cat "${work_dir}/open-tap-pr.log" >&2
fi
check_tap "on the first run" 9.9.9 "${cask_dir}/fabric.rb" 1
if ! grep -qF "both \`sha256\` values match" "${tap_pulls}"; then
  fail "open-tap-pr.sh opened the pull request without the review checklist"
fi
if ! grep -qF "(${release_run_url})" "${tap_pulls}"; then
  fail "open-tap-pr.sh opened the pull request without a link to the release run"
fi

# A re-run with the same cask only asks GitHub what is there.
if ! run_open_tap_pr 9.9.9 "${cask_dir}/fabric.rb"; then
  fail "open-tap-pr.sh failed on a re-run:"
  cat "${work_dir}/open-tap-pr.log" >&2
fi
check_tap "on a re-run" 9.9.9 "${cask_dir}/fabric.rb" 1
if [ "$(cat "${tap_calls}")" != query ]; then
  fail "open-tap-pr.sh changed something on a re-run: $(tr '\n' ' ' < "${tap_calls}")"
fi

# A re-run with a changed cask commits it to the open pull request's branch.
sed 's/^  version "9.9.9"$/  version "9.9.9" # changed/' "${cask_dir}/fabric.rb" > "${cask_dir}/changed.rb"
if ! run_open_tap_pr 9.9.9 "${cask_dir}/changed.rb"; then
  fail "open-tap-pr.sh failed on a re-run with a changed cask:"
  cat "${work_dir}/open-tap-pr.log" >&2
fi
check_tap "on a re-run with a changed cask" 9.9.9 "${cask_dir}/changed.rb" 2

check_tap_stops "with a tag instead of a version" v9.9.9 "${cask_dir}/fabric.rb"
check_tap_stops "with a cask file that doesn't exist" 9.9.9 "${cask_dir}/missing.rb"
check_tap_stops "with an empty GH_TOKEN" GH_TOKEN= 9.9.9 "${cask_dir}/fabric.rb"
check_tap_stops "with a TAP_REPOSITORY that isn't owner/name" TAP_REPOSITORY=a/b/c 9.9.9 "${cask_dir}/fabric.rb"
check_tap_stops "with a RELEASE_RUN_URL that isn't a GitHub Actions run" \
  "RELEASE_RUN_URL=https://example.com/actions/runs/1)" 9.9.9 "${cask_dir}/fabric.rb"

# GitHub refuses the commit when the branch moved on after the query, and the
# script stops before it opens a pull request.
new_tap
git -C "${tap_seed}" commit --quiet --allow-empty --message "chore: moved on"
git -C "${tap_seed}" push --quiet "${tap_origin}" HEAD:refs/heads/fabric-9.9.9
if run_open_tap_pr FAKE_GH_REPORTED_HEAD="${tap_main}" 9.9.9 "${cask_dir}/fabric.rb"; then
  fail "open-tap-pr.sh passed when GitHub refused the commit"
elif [ "$(tr '\n' ' ' < "${tap_calls}")" != "query createCommitOnBranch " ]; then
  fail "open-tap-pr.sh went on after GitHub refused the commit: $(tr '\n' ' ' < "${tap_calls}")"
elif [ -s "${tap_pulls}" ]; then
  fail "open-tap-pr.sh opened a pull request after GitHub refused the commit"
fi

# A retry after the pull request was merged, whose branch the tap deleted,
# and a re-run of a release older than main's change nothing.
new_tap "${cask_dir}/fabric.rb"
check_tap_untouched "when main already holds the cask" 9.9.9 "${cask_dir}/fabric.rb"
sed 's/^  version "9.9.9"$/  version "10.0.0"/' "${cask_dir}/fabric.rb" > "${cask_dir}/newer.rb"
new_tap "${cask_dir}/newer.rb"
check_tap_untouched "when main holds a newer version" 9.9.9 "${cask_dir}/fabric.rb"

# The same version with other hashes, as after a re-run of the macOS jobs,
# gets a pull request.
sed 's/^\(  sha256 arm:   "\)[0-9a-f]*/\1'"$(printf '0%.0s' {1..64})"'/' "${cask_dir}/fabric.rb" > "${cask_dir}/old-hashes.rb"
new_tap "${cask_dir}/old-hashes.rb"
if ! run_open_tap_pr 9.9.9 "${cask_dir}/fabric.rb"; then
  fail "open-tap-pr.sh failed when main holds the version with other hashes:"
  cat "${work_dir}/open-tap-pr.log" >&2
fi
check_tap "when main holds the version with other hashes" 9.9.9 "${cask_dir}/fabric.rb" 1

# A release after main's older version gets a pull request, also when only
# a version sort puts main's version first.
sed 's/^  version "9.9.9"$/  version "9.9.8"/' "${cask_dir}/fabric.rb" > "${cask_dir}/older.rb"
new_tap "${cask_dir}/older.rb"
if ! run_open_tap_pr 9.9.9 "${cask_dir}/fabric.rb"; then
  fail "open-tap-pr.sh failed when main holds an older version:"
  cat "${work_dir}/open-tap-pr.log" >&2
fi
check_tap "when main holds an older version" 9.9.9 "${cask_dir}/fabric.rb" 1
sed 's/^  version "9.9.9"$/  version "9.9.10"/' "${cask_dir}/fabric.rb" > "${cask_dir}/older-patch.rb"
sed 's/^  version "9.9.9"$/  version "9.10.0"/' "${cask_dir}/fabric.rb" > "${cask_dir}/fabric-9.10.0.rb"
new_tap "${cask_dir}/older-patch.rb"
if ! run_open_tap_pr 9.10.0 "${cask_dir}/fabric-9.10.0.rb"; then
  fail "open-tap-pr.sh failed for 9.10.0 when main holds 9.9.10:"
  cat "${work_dir}/open-tap-pr.log" >&2
fi
check_tap "for 9.10.0 when main holds 9.9.10" 9.10.0 "${cask_dir}/fabric-9.10.0.rb" 1

# A cask on main whose version isn't X.Y.Z stops the script after the query.
sed 's/^  version "9.9.9"$/  version "latest"/' "${cask_dir}/fabric.rb" > "${cask_dir}/latest.rb"
new_tap "${cask_dir}/latest.rb"
if run_open_tap_pr 9.9.9 "${cask_dir}/fabric.rb"; then
  fail "open-tap-pr.sh passed when main's cask has the version 'latest'"
elif [ "$(cat "${tap_calls}")" != query ]; then
  fail "open-tap-pr.sh went on when main's cask has the version 'latest': $(tr '\n' ' ' < "${tap_calls}")"
elif ! grep -qF "has the version 'latest'" "${work_dir}/open-tap-pr.log"; then
  fail "open-tap-pr.sh stopped on main's version 'latest' with another error:"
  cat "${work_dir}/open-tap-pr.log" >&2
fi

# sign-macos.sh checks its arguments and settings before anything that needs
# a Mac. scripts/testdata/linux-bin/uname makes it see Linux, so it never
# reaches a keychain even when these tests run on a Mac.
sign_bin_dir="${work_dir}/sign-bin"
mkdir -p "${sign_bin_dir}"
sign_args=(--bin-dir "${sign_bin_dir}" --notary-dir "${work_dir}/notary")
run_sign_macos() {
  (
    export PATH="${testdata}/linux-bin:${PATH}"
    export CLI_MACOS_TEAM_ID=ABCDE12345
    export APPLE_SIGNING_IDENTITY="Developer ID Application: Example Ltd (ABCDE12345)"
    export APPLE_DEVELOPER_ID_P12=bm90IGEgcmVhbCBwMTI= # base64 of "not a real p12"
    export APPLE_DEVELOPER_ID_P12_PASSWORD=test-password
    export APPLE_NOTARY_KEY=$'-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----'
    export APPLE_NOTARY_KEY_ID=KEY1234567
    export APPLE_NOTARY_ISSUER_ID=01234567-89ab-cdef-0123-456789abcdef
    for setting in "$@"; do
      export "${setting?}"
    done
    "${root}/scripts/sign-macos.sh" "${sign_args[@]}"
  ) > "${work_dir}/sign-macos.log" 2>&1
}
check_sign_stops() {
  local what="$1" message="$2"
  shift 2
  if run_sign_macos "$@"; then
    fail "sign-macos.sh passed ${what}"
  elif ! grep -qF -- "${message}" "${work_dir}/sign-macos.log"; then
    fail "sign-macos.sh ${what} didn't stop with '${message}':"
    cat "${work_dir}/sign-macos.log" >&2
  fi
}
check_sign_stops "on Linux" "macOS binaries are signed on macOS"
check_sign_stops "with no APPLE_NOTARY_KEY" "APPLE_NOTARY_KEY is not set" APPLE_NOTARY_KEY=
check_sign_stops "with a bad Team ID" "CLI_MACOS_TEAM_ID is not a 10-character Team ID" CLI_MACOS_TEAM_ID=abc
check_sign_stops "with another team's identity" "is not a Developer ID Application identity" \
  "APPLE_SIGNING_IDENTITY=Developer ID Application: Other (ZZZZZ99999)"
check_sign_stops "with a .p12 that isn't base64" "APPLE_DEVELOPER_ID_P12 is not base64 text" "APPLE_DEVELOPER_ID_P12=not base64!"
check_sign_stops "with a notary key that isn't a .p8" "APPLE_NOTARY_KEY is not the text" APPLE_NOTARY_KEY=secret
check_sign_stops "with a bad Key ID" "APPLE_NOTARY_KEY_ID is not a 10-character Key ID" APPLE_NOTARY_KEY_ID=key-1
check_sign_stops "with a bad Issuer ID" "APPLE_NOTARY_ISSUER_ID is not an Issuer ID" APPLE_NOTARY_ISSUER_ID=nope
check_sign_stops "with an upper-case Issuer ID" "APPLE_NOTARY_ISSUER_ID is not an Issuer ID" \
  APPLE_NOTARY_ISSUER_ID=01234567-89AB-CDEF-0123-456789ABCDEF
# The same checks for the arguments, with every setting valid.
check_sign_args_stop() {
  local what="$1" message="$2"
  shift 2
  sign_args=("$@")
  check_sign_stops "${what}" "${message}"
  sign_args=(--bin-dir "${sign_bin_dir}" --notary-dir "${work_dir}/notary")
}
check_sign_args_stop "with an unknown argument" "usage:" "${sign_args[@]}" --version 9.9.9
check_sign_args_stop "with no --notary-dir" "usage:" --bin-dir "${sign_bin_dir}"
check_sign_args_stop "with --bin-dir missing its value" "usage:" --notary-dir "${work_dir}/notary" --bin-dir
check_sign_args_stop "with a --bin-dir that isn't a directory" "is not a directory" \
  --bin-dir "${work_dir}/no-such-dir" --notary-dir "${work_dir}/notary"
if [ -e "${work_dir}/notary" ]; then
  fail "sign-macos.sh made the notary folder before its checks passed"
fi

if [ "${failures}" -ne 0 ]; then
  exit 1
fi
echo "Release scripts passed"
