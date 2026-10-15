#!/usr/bin/env bash
# Adds the macOS archives to a release's SHA256SUMS. Takes the SHA256SUMS
# file, downloaded from the release, and the archives, for example
# `scripts/macos-sums.sh SHA256SUMS dist/fabric-0.2.0-aarch64-apple-darwin.tar.gz
# dist/fabric-0.2.0-x86_64-apple-darwin.tar.gz`, and rewrites the file in place.
# Run by the macos-publish job of .github/workflows/release.yaml.
#
# Every line already there is kept, except one for a file of the same name as
# an archive, which is replaced, so a re-run never adds a second line for the
# same archive. Lines look like `sha256sum` writes them, `<sha256>  <file>`,
# sorted by file name as the shared release workflow sorts them. A line that
# looks different, an empty file or a missing archive stops the script and
# leaves the file as it was.
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <SHA256SUMS> <archive>..." >&2
  exit 2
fi
sums="$1"
shift

if [ ! -s "${sums}" ]; then
  echo "error: ${sums} is missing or empty" >&2
  exit 1
fi
if LC_ALL=C grep -qEv '^[0-9a-f]{64}  [A-Za-z0-9._+-]+$' "${sums}"; then
  echo "error: ${sums} has a line that isn't '<sha256>  <file>'" >&2
  exit 1
fi

if command -v sha256sum > /dev/null 2>&1; then
  hash_tool=(sha256sum)
else
  hash_tool=(shasum -a 256)
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT
new_lines="${work_dir}/new"
: > "${new_lines}"
for archive in "$@"; do
  name="$(basename -- "${archive}")"
  if [ ! -f "${archive}" ]; then
    echo "error: ${archive} is missing" >&2
    exit 1
  fi
  if ! [[ "${name}" =~ ^[A-Za-z0-9._+-]+\.tar\.gz$ ]]; then
    echo "error: ${name} isn't an archive name SHA256SUMS can hold" >&2
    exit 1
  fi
  if awk -v name="${name}" '$2 == name { found = 1 } END { exit !found }' "${new_lines}"; then
    echo "error: ${name} is given twice" >&2
    exit 1
  fi
  hash="$("${hash_tool[@]}" < "${archive}" | awk '{ print $1 }')"
  printf '%s  %s\n' "${hash}" "${name}" >> "${new_lines}"
done

# Old lines whose file name is one of the archives are dropped, then the new
# lines are added and everything is sorted by file name.
LC_ALL=C awk 'NR == FNR { replaced[$2] = 1; next } !($2 in replaced)' "${new_lines}" "${sums}" \
  | cat - "${new_lines}" \
  | LC_ALL=C sort -k2,2 > "${work_dir}/SHA256SUMS"
mv -- "${work_dir}/SHA256SUMS" "${sums}"
