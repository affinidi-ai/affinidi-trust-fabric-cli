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

  version "9.9.9"
  sha256 arm:   "48a8956d28f6619531c92d18b1caef7c7edef78f56fda9db9ac6f93510ab4a1a",
         intel: "0e38ce56670945f0c0d03fc0eaf4a5b66a8fb7b906f9b1e9444a23883b7ed89e"

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
