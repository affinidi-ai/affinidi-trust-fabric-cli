# Contributing

Affinidi Trust Fabric CLI is a single Rust binary, `fabric`. To propose a change, first discuss it by creating a new [GitHub issue](https://github.com/affinidi-ai/affinidi-trust-fabric-cli/issues/new). To report a security vulnerability, follow [`SECURITY.md`](SECURITY.md) instead.

## Development Requirements

- Rust `1.85` or newer, 2024 Edition (the minimum is declared in [`Cargo.toml`](Cargo.toml))
- An OS credential store: the macOS Keychain, Windows Credential Manager, or Linux Secret Service

For building, signing, and running the source, see [`docs/development/GETTING_STARTED.md`](docs/development/GETTING_STARTED.md). To find your way around the code, start with [`ARCHITECTURE.md`](ARCHITECTURE.md). For the recurring change shapes, such as adding a command or a table layout, see [`docs/development/MAKING_CHANGES.md`](docs/development/MAKING_CHANGES.md).

## Code Quality Expectations

1. Make the smallest correct change, with no dead code.
2. Cover changes with tests, positive and negative cases, and assert what is printed or sent rather than just the absence of errors. Don't mock the gateway: tests run against a scripted local HTTP server. [`docs/development/TESTING.md`](docs/development/TESTING.md) explains the layers and helpers.
3. Write comments that explain *why*, such as a gateway behaviour or a security reason, not *what* the code does.
4. Use clear, unambiguous names; avoid single letters and abbreviations.
5. Never print, log, or put tokens or secrets in error messages.
6. Treat help text as documentation. A new or changed command needs an accurate one-line summary, and an explanation and examples when it takes a JSON document, can't be undone, or has flags that interact.
7. Keep docs in sync with code in the same change (see [`docs/README.md`](docs/README.md)). Don't edit [`CHANGELOG.md`](CHANGELOG.md); it is written from pull request titles when a release is made (see [Releasing](#releasing)).

## Commits

Commits:

- **must follow [Conventional Commits](https://www.conventionalcommits.org)**: `feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`, and so on, followed by a summary. The repository rejects other commit messages.
- **should be signed** with a key GitHub can verify. See GitHub's guide to [signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

Pull requests are squash-merged, the only merge method the repository allows, so the pull request title becomes the commit on `main`; write it in the same format.

## Before Opening A Pull Request

Run the local checks and make sure CI passes:

1. `cargo fmt --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test`
4. If you added or changed a dependency: `cargo deny check`
5. If you changed the release scripts in `scripts/`: `shellcheck scripts/*.sh` and `scripts/test-release-scripts.sh`

CI also runs a dependency audit, a security scan, and a coverage check that requires at least 80% coverage. Pull requests from forks don't run the security scan, because forks don't receive repository secrets; it runs once the change reaches `main`.

## Releasing

Releases are automatic. Once the [`checks`](.github/workflows/checks.yaml) workflow passes on a merge to `main`, the [`version`](.github/workflows/version.yaml) workflow reads the titles of the commits merged since the last release, so the pull request title decides what gets released:

| Pull request title | Release |
| --- | --- |
| `fix: ...`, `perf: ...` or `revert: ...` | Patch, for example `0.2.0` to `0.2.1` |
| `feat: ...` | Minor, for example `0.2.1` to `0.3.0` |
| `feat!: ...`, `fix!: ...`, or `BREAKING CHANGE:` in the commit body | Breaking. A minor release, for example `0.3.0` to `0.4.0`, until the rule that keeps breaking changes minor is removed from [`release.config.mjs`](.github/release/release.config.mjs); removing it is how `1.0.0` is made |
| `docs:`, `chore:`, `ci:`, `build:`, `refactor:`, `style:`, `test:` | Nothing on its own; it goes out with the next release |

The release notes list `feat` under New, `fix`, `perf` and `revert` under Fixes, and breaking changes first. A fix with the `security` or `deps` scope, such as `fix(security): ...` or `fix(deps): update quinn-proto`, is listed under Security. Write the title for someone reading the release notes, because it is copied there word for word.

When a release is due, the release bot sets the new version in `Cargo.toml` and `Cargo.lock`, adds the release notes to the top of [`CHANGELOG.md`](CHANGELOG.md), and commits that to `main` as `chore: release vX.Y.Z` through the GitHub API, so GitHub signs the commit and shows it as verified. It then pushes the tag `vX.Y.Z` on that commit. The tag starts the [`release`](.github/workflows/release.yaml) workflow, which builds the Linux binaries, publishes them with a `SHA256SUMS` file to a GitHub Release, and sets the release notes from `CHANGELOG.md` along with the authors of the pull requests in it. Beside that it builds the macOS binaries for Apple silicon and Intel, signs and notarizes them, and adds them and their lines in `SHA256SUMS` to the same release once it is published.

Never edit `CHANGELOG.md`, the version in `Cargo.toml`, or the `v*` tags by hand. The first run of the workflow, before any `v*` tag exists, tags the version already in `Cargo.toml` (`v0.1.0`) at the commit that added its `CHANGELOG.md` section, then releases anything merged after it in the same run.

If `main` has moved on by the time the checks pass on a commit, that run releases nothing, and the newer commit releases both once its own checks pass. To retry a failed release, run the `version` workflow by hand on `main`. If the release commit `chore: release vX.Y.Z` reached `main` but its tag didn't, that run first tags the release commit, so the version isn't made twice.

### Release setup

A repository admin sets these up once, before the release bot's secrets are added. Until both secrets are set, the `version` workflow passes with a notice and releases nothing.

1. A `main` environment that only `main` can deploy to, holding the release bot app's ID as `RELEASE_BOT_APP_ID` and its private key as `RELEASE_BOT_PRIVATE_KEY`, both as secrets. If it doesn't exist yet, the first run of the `version` workflow creates it with no branch limit, so set it up first.
2. The release bot app as a bypass actor on the `release-tags` tag ruleset, so it can push `v*` tags.
3. Rebase merging and merge commits turned off, so squash merging is the only merge method.
4. A `macos-release` environment that only `v*` tags can deploy to, holding the secrets in [macOS signing](#macos-signing). If it doesn't exist yet, the first `v*` tag creates it with no tag limit, so set it up first.
5. Immutable releases left off, because the macOS archives and their `SHA256SUMS` lines are added after the release is published.

### macOS signing

The `macos-build` job builds the macOS binaries with no secrets. The `macos-sign` job then signs them with Affinidi's Developer ID and notarizes them with Apple, using [`scripts/sign-macos.sh`](scripts/sign-macos.sh). It runs in a `macos-release` environment that only `v*` tags can deploy to, and that environment holds these secrets:

| Secret | Value |
| --- | --- |
| `APPLE_SIGNING_IDENTITY` | The certificate's name, `Developer ID Application: <name> (8Q88B239RG)` |
| `APPLE_DEVELOPER_ID_P12` | The Developer ID Application certificate and its private key as a `.p12` exported from Keychain Access, in base64: `base64 -i developer-id.p12 \| pbcopy`. A `.p12` made with OpenSSL 3 needs `openssl pkcs12 -export -legacy`, or macOS can't import it |
| `APPLE_DEVELOPER_ID_P12_PASSWORD` | The password of that `.p12` |
| `APPLE_NOTARY_KEY` | The App Store Connect API key, the whole text of its `.p8` file including the `-----BEGIN PRIVATE KEY-----` line |
| `APPLE_NOTARY_KEY_ID` | That key's 10-character Key ID |
| `APPLE_NOTARY_ISSUER_ID` | The team's Issuer ID from App Store Connect, a UUID in lower case as App Store Connect shows it |

The Team ID `8Q88B239RG` is set as `CLI_MACOS_TEAM_ID` in the workflow, because every signed binary shows it, so it isn't a secret. The script checks the shape of every value before it signs anything, and asks Apple whether the notary key works.

The Linux release is published first and doesn't wait for macOS. If signing or notarizing fails, the release has only the Linux binaries until the cause is fixed and the failed jobs are re-run from the workflow run's page. Re-run them within 7 days, because the re-run signs the unsigned binaries the first run built, and those are kept for 7 days. After that, re-run the `macos-build` job instead, which builds them again and re-runs the signing and publishing jobs after it. A re-run replaces the macOS archives and their `SHA256SUMS` lines, so it never adds them twice. If a failed upload left the release with no `SHA256SUMS`, the re-run rebuilds it from the Linux archives; each run also keeps the file it uploads as the `release-sha256sums` artifact.

Until the repository is public, the Homebrew tap [`affinidi-ai/homebrew-tap`](https://github.com/affinidi-ai/homebrew-tap) is updated by hand: after a release, open a pull request there that sets `fabric` to the new version and the SHA-256 of both macOS archives from the release's `SHA256SUMS`. The tap has no `fabric` entry yet, so the first such pull request adds it.

## Code of Conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we as
contributors and maintainers pledge to make participation in our project and
our community a harassment-free experience for everyone, regardless of age, body
size, disability, ethnicity, gender identity and expression, level of experience,
nationality, personal appearance, race, religion, or sexual identity and
orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment
include:

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members
- Avoiding obvious comments about things like code styling and indentation.
  **If you see yourself wanting to do that more than once - open an issue to update the
  clippy/rustfmt rules to address this concern once and for all. Code reviews should be
  about logic, not indenting or adding more newlines.**

Examples of unacceptable behavior by participants include:

- The use of sexualized language or imagery and unwelcome sexual attention or
  advances
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information, such as a physical or electronic
  address, without explicit permission
- Other conduct which could reasonably be considered inappropriate in a
  professional setting

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
