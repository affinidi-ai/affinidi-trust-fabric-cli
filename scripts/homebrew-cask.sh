#!/usr/bin/env bash
# Prints the Homebrew cask of one release, for example
# `scripts/homebrew-cask.sh 0.2.0 dist/SHA256SUMS > dist/fabric.rb`. Run by
# .github/workflows/homebrew-tap.yaml after a release, before
# scripts/open-tap-pr.sh opens the pull request that puts it in the tap as
# Casks/fabric.rb.
#
# Each sha256 is taken from the release's SHA256SUMS line for that macOS
# archive. A missing line, a line given twice or a value that isn't a sha256
# stops the script, so a release without both macOS archives never reaches
# brew users.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <X.Y.Z> <SHA256SUMS>" >&2
  exit 2
fi
version="$1"
sums="$2"
if ! [[ "${version}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "error: the version must look like 1.2.3, got '${version}'" >&2
  exit 1
fi
if [ ! -s "${sums}" ]; then
  echo "error: ${sums} is missing or empty" >&2
  exit 1
fi

# Prints the sha256 of one archive from SHA256SUMS, which `sha256sum` wrote
# as `<sha256>  <file>` lines.
archive_sha256() {
  local name="fabric-${version}-$1-apple-darwin.tar.gz" hashes
  hashes="$(awk -v name="${name}" '$2 == name { print $1 }' "${sums}")"
  if [ -z "${hashes}" ]; then
    echo "error: ${sums} has no line for ${name}" >&2
    return 1
  fi
  if ! [[ "${hashes}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "error: ${sums} doesn't hold one sha256 for ${name}" >&2
    return 1
  fi
  echo "${hashes}"
}
arm_sha256="$(archive_sha256 aarch64)"
intel_sha256="$(archive_sha256 x86_64)"

# The layout and stanza order follow Casks/boris.rb in the tap, which
# `brew style` checks. desc is the description in Cargo.toml, which
# scripts/test-release-scripts.sh checks.
cat << EOF
# The fabric CLI cask, rendered by scripts/homebrew-cask.sh in
# affinidi-ai/affinidi-trust-fabric-cli for one release. The release opens a
# pull request on the tap with this file; it never pushes, and nobody edits
# it by hand. The url is the versioned release archive and each sha256
# comes from the release's SHA256SUMS. There is no postflight and no
# quarantine removal: the binary is Developer ID signed and notarized, so
# Gatekeeper's check of the quarantined download is real.
#
#   brew install --cask affinidi-ai/tap/fabric
cask "fabric" do
  arch arm: "aarch64", intel: "x86_64"

  version "${version}"
  sha256 arm:   "${arm_sha256}",
         intel: "${intel_sha256}"

  url "https://github.com/affinidi-ai/affinidi-trust-fabric-cli/releases/download/v#{version}/fabric-#{version}-#{arch}-apple-darwin.tar.gz"
  name "fabric"
  desc "Command-line client for Affinidi appliances, starting with Agent Gateway"
  homepage "https://github.com/affinidi-ai/affinidi-trust-fabric-cli"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on macos: :monterey

  # The archive holds a folder named after itself, as the Linux ones do.
  binary "fabric-#{version}-#{arch}-apple-darwin/fabric"
end
EOF
