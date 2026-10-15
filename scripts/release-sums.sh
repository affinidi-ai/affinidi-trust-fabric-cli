#!/usr/bin/env bash
# Downloads a release's SHA256SUMS into a folder, for example
# `scripts/release-sums.sh v0.2.0 dist` writes dist/SHA256SUMS. Run by the
# macos-publish job of .github/workflows/release.yaml before
# scripts/macos-sums.sh adds the macOS lines.
#
# A release can lose its SHA256SUMS: `gh release upload --clobber` deletes the
# old file before it uploads the new one, so a failed upload leaves none. Only
# then, when the release lists no SHA256SUMS, the file is rebuilt from the
# release's Linux archives, hashed and sorted as the shared release workflow
# writes it. Any other gh failure stops the script, so a network error never
# replaces a good SHA256SUMS with a rebuilt one.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <tag> <dir>" >&2
  exit 2
fi
tag="$1"
dir="$2"

if ! [[ "${tag}" =~ ^v[0-9A-Za-z.+-]+$ ]]; then
  echo "error: ${tag} is not a release tag like v0.2.0" >&2
  exit 1
fi
if [ ! -d "${dir}" ]; then
  echo "error: ${dir} is not a directory" >&2
  exit 1
fi
version="${tag#v}"

assets="$(gh release view "${tag}" --json assets --jq '.assets[].name')"
if grep -qxF SHA256SUMS <<< "${assets}"; then
  gh release download "${tag}" --pattern SHA256SUMS --dir "${dir}" --clobber
  exit 0
fi
echo "::warning::Release ${tag} has no SHA256SUMS, so its Linux lines are rebuilt from the Linux archives"

if command -v sha256sum > /dev/null 2>&1; then
  hash_tool=(sha256sum)
else
  hash_tool=(shasum -a 256)
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT
# The targets the shared workflow builds by default (linux-binaries in
# release.yaml sets none), in the order `sha256sum *.tar.gz` lists them.
for target in aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu; do
  name="fabric-${version}-${target}.tar.gz"
  if ! grep -qxF "${name}" <<< "${assets}"; then
    echo "error: release ${tag} has neither SHA256SUMS nor ${name}" >&2
    exit 1
  fi
  gh release download "${tag}" --pattern "${name}" --dir "${work_dir}"
  hash="$("${hash_tool[@]}" < "${work_dir}/${name}" | awk '{ print $1 }')"
  printf '%s  %s\n' "${hash}" "${name}" >> "${work_dir}/SHA256SUMS"
done
mv -- "${work_dir}/SHA256SUMS" "${dir}/SHA256SUMS"
