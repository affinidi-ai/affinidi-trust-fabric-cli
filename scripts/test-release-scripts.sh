#!/usr/bin/env bash
# Checks the release scripts without a release or the network:
# scripts/set-version.sh changes exactly the two version lines in a copy of
# Cargo.toml and Cargo.lock, scripts/changelog-section.sh finds the right
# section of scripts/testdata/CHANGELOG.md, and scripts/commit-release.sh
# commits the release files on top of the checked out commit and moves HEAD to
# that commit, or changes nothing. Run by .github/workflows/checks.yaml; the
# working tree is never changed.
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

if [ "${failures}" -ne 0 ]; then
  exit 1
fi
echo "Release scripts passed"
