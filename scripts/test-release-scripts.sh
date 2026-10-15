#!/usr/bin/env bash
# Checks the release scripts without a release or the network:
# scripts/set-version.sh changes exactly the two version lines in a copy of
# Cargo.toml and Cargo.lock, scripts/changelog-section.sh finds the right
# section of scripts/testdata/CHANGELOG.md, and scripts/commit-release.sh
# commits the release files on top of the checked out commit and moves HEAD to
# that commit, or changes nothing. scripts/macos-sums.sh adds the macOS
# archives to SHA256SUMS once, even on a re-run, scripts/release-sums.sh
# rebuilds a release's SHA256SUMS only when it is missing, and
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
