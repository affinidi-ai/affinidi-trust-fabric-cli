#!/usr/bin/env bash
# Checks the release scripts without a release: scripts/set-version.sh changes
# exactly the two version lines in a copy of Cargo.toml and Cargo.lock, and
# scripts/changelog-section.sh finds the right section of
# scripts/testdata/CHANGELOG.md. Run by .github/workflows/checks.yaml; the
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

if [ "${failures}" -ne 0 ]; then
  exit 1
fi
echo "Release scripts passed"
