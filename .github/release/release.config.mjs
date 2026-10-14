// semantic-release settings, used by scripts/release.sh.
//
// The next version comes from the conventional commit titles on `main` since
// the last `v*` tag. The release commit sets that version in Cargo.toml and
// Cargo.lock, adds the release notes to CHANGELOG.md, and is tagged
// `v<version>`. The tag starts .github/workflows/release.yaml, which builds and
// publishes the binaries.
import createPreset from "conventional-changelog-conventionalcommits";

// Order matters twice: a commit goes to the first entry that matches its type
// and scope, and sections are printed in the order they first appear here.
// `perf` comes before the security entries so Fixes is printed before Security.
const presetConfig = {
  types: [
    { type: "feat", section: "✨ New" },
    { type: "perf", section: "🛠️ Fixes" },
    { type: "fix", scope: "security", section: "🔒 Security" },
    { type: "fix", scope: "deps", section: "🔒 Security" },
    { type: "fix", section: "🛠️ Fixes" },
    { type: "revert", section: "🛠️ Fixes" },
    { type: "docs", hidden: true },
    { type: "chore", hidden: true },
    { type: "ci", hidden: true },
    { type: "build", hidden: true },
    { type: "refactor", hidden: true },
    { type: "style", hidden: true },
    { type: "test", hidden: true },
  ],
};

// The preset hardcodes the breaking changes heading. Swap in ours, and stop the
// release if a preset upgrade changes the template so the swap no longer applies.
const PRESET_BREAKING_HEADING = "### ⚠ {{title}}";
const { writer } = await createPreset(presetConfig);
if (!writer.mainTemplate.includes(PRESET_BREAKING_HEADING)) {
  throw new Error(
    `conventional-changelog-conventionalcommits no longer has "${PRESET_BREAKING_HEADING}" in its template; update release.config.mjs`,
  );
}
const mainTemplate = writer.mainTemplate.replace(PRESET_BREAKING_HEADING, "### 🚨 Breaking changes");

// Must match the top of CHANGELOG.md exactly. The changelog plugin puts each
// release's notes right after this text, above the older releases.
const changelogTitle = `# Changelog

All notable changes to Affinidi Trust Fabric CLI are documented in this file. Entries are written from pull request titles when a release is made, and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).`;

export default {
  branches: ["main"],
  tagFormat: "v${version}",
  plugins: [
    [
      "@semantic-release/commit-analyzer",
      {
        preset: "conventionalcommits",
        presetConfig,
        // A breaking change bumps the minor version for as long as the first
        // rule is here, whatever the version; removing it makes the next
        // breaking change release 1.0.0. A `revert:` title only makes a
        // release by default when its body says "This reverts commit", so the
        // second rule makes every revert a patch.
        releaseRules: [
          { breaking: true, release: "minor" },
          { type: "revert", release: "patch" },
        ],
      },
    ],
    [
      "@semantic-release/release-notes-generator",
      {
        preset: "conventionalcommits",
        presetConfig,
        writerOpts: { mainTemplate },
      },
    ],
    ["@semantic-release/changelog", { changelogFile: "CHANGELOG.md", changelogTitle }],
    ["@semantic-release/exec", { prepareCmd: "scripts/set-version.sh ${nextRelease.version}" }],
    [
      "@semantic-release/git",
      {
        assets: ["CHANGELOG.md", "Cargo.toml", "Cargo.lock"],
        // The version workflow skips the bot's commits that start with
        // `chore: release v`, and scripts/release.sh finds an untagged release
        // commit by this message, so change all three together. The message
        // must also pass the repository's conventional commit rule.
        message: "chore: release v${nextRelease.version}",
      },
    ],
  ],
};
