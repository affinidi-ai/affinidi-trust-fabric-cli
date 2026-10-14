#!/usr/bin/env bash
# Sets the package version in Cargo.toml and Cargo.lock to the version given as
# the only argument, for example `scripts/set-version.sh 0.2.0`.
#
# semantic-release runs this while it prepares a release, so the release commit
# carries the new version. It edits the files as text, without cargo or the
# network, and fails unless exactly one version line changed in each file.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <X.Y.Z>" >&2
  exit 2
fi
version="$1"
if ! [[ "${version}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "error: the version must look like 1.2.3, got '${version}'" >&2
  exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="${root}/Cargo.toml"
lockfile="${root}/Cargo.lock"

package_name="$(awk '
  /^\[/ { in_package = ($0 == "[package]") }
  in_package && match($0, /^name[ \t]*=[ \t]*"[^"]+"/) {
    sub(/^name[ \t]*=[ \t]*"/, ""); sub(/".*$/, ""); print; exit
  }
' "${manifest}")"
if [ -z "${package_name}" ]; then
  echo "error: no name in the [package] section of ${manifest}" >&2
  exit 1
fi

# Every `version = ` line in the [package] section; other sections such as
# [dependencies] are left alone. Prints the edited file and writes the number
# of lines it changed to the file named by the second argument.
edit_manifest() {
  awk -v version="${version}" -v count_file="$2" '
    /^\[/ { in_package = ($0 == "[package]") }
    in_package && /^version[ \t]*=/ { print "version = \"" version "\""; changed++; next }
    { print }
    END { print changed + 0 > count_file }
  ' "$1"
}

# The `version = ` line of the [[package]] entry whose name is this package.
# Same output as edit_manifest.
edit_lockfile() {
  awk -v version="${version}" -v package="${package_name}" -v count_file="$2" '
    /^\[\[package\]\]$/ { ours = 0 }
    $0 == "name = \"" package "\"" { ours = 1 }
    ours && /^version = / { print "version = \"" version "\""; changed++; ours = 0; next }
    { print }
    END { print changed + 0 > count_file }
  ' "$1"
}

# Runs the edit into a temporary copy of the file and checks that exactly one
# line changed and the content is different. Neither file is written until
# both edits pass, so a failed check leaves both untouched.
work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

check_edit() {
  local file="$1" edit="$2" edited="$3" changed
  "${edit}" "${file}" "${work_dir}/count" > "${edited}"
  changed="$(cat "${work_dir}/count")"
  if [ "${changed}" != "1" ]; then
    echo "error: expected to change one version line in ${file}, changed ${changed:-0}" >&2
    exit 1
  fi
  # awk always ends its output with a newline. Drop it again when the original
  # file has none, so only the version line shows up in the diff.
  if [ -n "$(tail -c 1 "${file}")" ]; then
    local content
    content="$(cat "${edited}")"
    printf '%s' "${content}" > "${edited}"
  fi
  if cmp -s "${file}" "${edited}"; then
    echo "error: ${file} is already at version ${version}" >&2
    exit 1
  fi
}

check_edit "${manifest}" edit_manifest "${work_dir}/Cargo.toml"
check_edit "${lockfile}" edit_lockfile "${work_dir}/Cargo.lock"
# Copied over rather than moved, so the files keep their permissions.
cat "${work_dir}/Cargo.toml" > "${manifest}"
cat "${work_dir}/Cargo.lock" > "${lockfile}"

echo "Set ${package_name} to ${version} in Cargo.toml and Cargo.lock"
